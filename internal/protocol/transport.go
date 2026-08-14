package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

type tcpProxy struct {
	Scheme string
	Host   string
	Port   string
	User   string
	Pass   string
}

// ParseTCPProxy validates and parses a proxy URL of the form
// socks5://[user:pass@]host:port. Returns (nil, nil) for empty input.
func ParseTCPProxy(value string) (*tcpProxy, error) {
	return parseTCPProxy(value)
}

// DialTCP dials host:port, optionally through the given SOCKS5 proxy. When
// proxyValue is empty it dials directly. When fallbackDirect is true and the
// proxy dial fails, it transparently retries with a direct connection.
func DialTCP(ctx context.Context, host string, port int, timeout time.Duration, proxyValue string, fallbackDirect bool) (net.Conn, error) {
	return dialTCP(ctx, host, port, timeout, proxyValue, fallbackDirect)
}

func parseTCPProxy(value string) (*tcpProxy, error) {
	if value == "" {
		return nil, nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("tcp_proxy must use socks5://")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("tcp_proxy must include host and port")
	}
	p := &tcpProxy{
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   u.Port(),
	}
	if u.User != nil {
		p.User = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			p.Pass = pass
		}
	}
	return p, nil
}

func dialTCP(ctx context.Context, host string, port int, timeout time.Duration, proxyValue string, fallbackDirect bool) (net.Conn, error) {
	proxy, err := parseTCPProxy(proxyValue)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return dialDirect(ctx, host, port, timeout)
	}
	conn, err := dialViaProxy(ctx, proxy, host, port, timeout)
	if err == nil {
		return conn, nil
	}
	if !fallbackDirect {
		return nil, err
	}
	return dialDirect(ctx, host, port, timeout)
}

func dialDirect(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	var d net.Dialer
	if timeout > 0 {
		d.Timeout = timeout
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func dialViaProxy(ctx context.Context, proxy *tcpProxy, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	conn, err := dialDirect(ctx, proxy.Host, mustAtoi(proxy.Port), timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}
	err = socks5Connect(conn, proxy, targetHost, targetPort)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5Connect performs SOCKS5 handshake with optional username/password
// authentication (RFC 1928 + RFC 1929).
func socks5Connect(conn net.Conn, proxy *tcpProxy, targetHost string, targetPort int) error {
	// --- 1. 方法协商 ---
	// 如果配置了账号密码，同时声明支持 no-auth(0x00) 和 user/pass(0x02)
	// 否则只声明 no-auth
	var greeting []byte
	if proxy.User != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02} // VER=5, NMETHODS=2, no-auth, user/pass
	} else {
		greeting = []byte{0x05, 0x01, 0x00} // VER=5, NMETHODS=1, no-auth
	}
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	// --- 2. 读取服务器选择的方法 ---
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("SOCKS5 invalid version in greeting reply: %d", buf[0])
	}
	switch buf[1] {
	case 0x00:
		// 无需认证，直接进入 CONNECT
	case 0x02:
		// 服务器要求用户名/密码认证 (RFC 1929)
		if proxy.User == "" {
			return fmt.Errorf("SOCKS5 server requires auth but no credentials provided")
		}
		if err := socks5UsernamePasswordAuth(conn, proxy.User, proxy.Pass); err != nil {
			return err
		}
	case 0xFF:
		return fmt.Errorf("SOCKS5 server rejected all offered authentication methods")
	default:
		return fmt.Errorf("SOCKS5 unsupported auth method selected by server: %d", buf[1])
	}

	// --- 3. CONNECT 请求 ---
	hostBytes := []byte(targetHost)
	if len(hostBytes) > 255 {
		return fmt.Errorf("SOCKS5 target host too long")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
	req = append(req, hostBytes...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(targetPort))
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// --- 4. 读取 CONNECT 响应 ---
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 5 || head[1] != 0 {
		return fmt.Errorf("SOCKS5 connect failed: VER=%d REP=%d", head[0], head[1])
	}
	switch head[3] {
	case 1: // IPv4
		_, err := io.CopyN(io.Discard, conn, 6)
		return err
	case 3: // 域名
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, conn, int64(ln[0])+2)
		return err
	case 4: // IPv6
		_, err := io.CopyN(io.Discard, conn, 18)
		return err
	default:
		return fmt.Errorf("SOCKS5 unsupported bind address type: %d", head[3])
	}
}

// socks5UsernamePasswordAuth performs RFC 1929 username/password sub-negotiation.
// 报文格式:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
//
// 服务器回复:
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// STATUS=0x00 表示成功，其他值表示失败
func socks5UsernamePasswordAuth(conn net.Conn, user, pass string) error {
	if len(user) > 255 {
		return fmt.Errorf("SOCKS5 username too long (max 255)")
	}
	if len(pass) > 255 {
		return fmt.Errorf("SOCKS5 password too long (max 255)")
	}

	// 构造认证请求
	authReq := []byte{0x01, byte(len(user))} // VER=1(用户名/密码子协议版本), ULEN
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(pass))) // PLEN
	authReq = append(authReq, []byte(pass)...)

	if _, err := conn.Write(authReq); err != nil {
		return err
	}

	// 读取认证响应
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("SOCKS5 auth: invalid sub-negotiation version: %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 authentication failed: status %d", resp[1])
	}
	return nil
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
