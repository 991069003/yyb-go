"""
Rotate SOCKS5 proxy: listens on 127.0.0.1:1080, for each client CONNECT
request fetches a fresh SOCKS5 upstream from 51daili and relays traffic.
"""
import socket
import threading
import sys
import time
import urllib.request

PROXY_API = (
    ""
)
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1080
UPSTREAM_TIMEOUT = 20


def fetch_proxy():
    """Fetch a fresh SOCKS5 upstream IP:PORT from 51daili."""
    try:
        with urllib.request.urlopen(PROXY_API, timeout=10) as r:
            line = r.read().decode("utf-8", errors="ignore").strip().splitlines()
        if not line:
            return None, None
        host, port = line[0].strip().split(":")
        return host, int(port)
    except Exception as e:
        log(f"fetch_proxy failed: {e}")
        return None, None


def log(msg):
    sys.stderr.write(f"[rotor] {msg}\n")
    sys.stderr.flush()


def socks5_connect_via(target_host, target_port, upstream_host, upstream_port):
    """Open a SOCKS5 connection to target through the upstream proxy."""
    s = socket.create_connection((upstream_host, upstream_port), timeout=UPSTREAM_TIMEOUT)
    # Greeting: ver=5, 1 method, no-auth
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 0x05:
        s.close()
        raise RuntimeError("bad SOCKS5 greeting reply")
    method = resp[1]
    if method == 0x02:
        # user/pass auth - just send dummy
        s.sendall(b"\x01\x01\x00\x01\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[1] != 0x00:
            s.close()
            raise RuntimeError("SOCKS5 auth failed")
    elif method != 0x00:
        s.close()
        raise RuntimeError(f"unsupported SOCKS5 method {method}")

    # CONNECT request
    if ":" in target_host and not target_host.replace(".", "").replace(":", "").isdigit():
        # domain
        b = target_host.encode("idna") if hasattr(target_host, "encode") else target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(b)]) + b + target_port.to_bytes(2, "big")
    else:
        try:
            ip4 = socket.inet_aton(target_host)
            req = b"\x05\x01\x00\x01" + ip4 + target_port.to_bytes(2, "big")
        except OSError:
            b = target_host.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(b)]) + b + target_port.to_bytes(2, "big")

    s.sendall(req)
    resp = s.recv(32)
    if len(resp) < 2 or resp[1] != 0x00:
        s.close()
        raise RuntimeError(f"SOCKS5 connect refused (rep={resp[1] if len(resp)>=2 else '?'})")
    return s


def relay(src, dst, name):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client, addr):
    try:
        # SOCKS5 greeting
        data = client.recv(512)
        if len(data) < 2 or data[0] != 0x05:
            client.close()
            return
        nmethods = data[1]
        # methods are already in `data` (offset 2..2+nmethods), no extra recv needed
        client.sendall(b"\x05\x00")  # no-auth selected

        # CONNECT request
        head = client.recv(4)
        if len(head) < 4 or head[0] != 0x05 or head[1] != 0x01:
            client.close()
            return
        atype = head[3]
        if atype == 0x01:
            host = socket.inet_ntoa(client.recv(4))
        elif atype == 0x03:
            ln = client.recv(1)[0]
            host = client.recv(ln).decode("utf-8", errors="ignore")
        elif atype == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close()
            return
        port = int.from_bytes(client.recv(2), "big")

        # Fetch fresh upstream
        up_host, up_port = fetch_proxy()
        if not up_host:
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close()
            return

        log(f"{addr[0]}:{addr[1]} -> {host}:{port} via {up_host}:{up_port}")

        try:
            upstream = socks5_connect_via(host, port, up_host, up_port)
        except Exception as e:
            log(f"upstream connect failed via {up_host}:{up_port}: {e}")
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close()
            return

        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        t1 = threading.Thread(target=relay, args=(client, upstream, "c->u"), daemon=True)
        t2 = threading.Thread(target=relay, args=(upstream, client, "u->c"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        log(f"{addr[0]}:{addr[1]} closed {host}:{port}")
    except Exception as e:
        log(f"handler error: {e}")
        try:
            client.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(256)
    log(f"SOCKS5 rotor listening on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
