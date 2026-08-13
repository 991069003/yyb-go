package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/qr"
)

// proxyConfigFile 存储代理配置的 JSON 文件名
const proxyConfigFile = "proxy_config.json"

// proxyConfigData 持久化的代理配置
type proxyConfigData struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
}

// ToURL 拼接成完整的代理 URL
func (p proxyConfigData) ToURL() string {
	if p.Scheme == "" || p.Host == "" || p.Port == "" {
		return ""
	}
	if p.User != "" && p.Pass != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%s", p.Scheme, p.User, p.Pass, p.Host, p.Port)
	}
	if p.User != "" {
		return fmt.Sprintf("%s://%s@%s:%s", p.Scheme, p.User, p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%s", p.Scheme, p.Host, p.Port)
}

// proxyConfigPath 返回代理配置文件的完整路径
func (a *App) proxyConfigPath() string {
	return filepath.Join(a.cfg.ResourceRoot, proxyConfigFile)
}

// loadProxyConfigFromFile 从文件加载持久化的代理配置，返回代理 URL
func loadProxyConfigFromFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var p proxyConfigData
	if err := json.Unmarshal(data, &p); err != nil {
		return ""
	}
	return p.ToURL()
}

// loadProxyConfigDataFromFile 从文件加载持久化的代理配置，返回结构体（含密码）
func loadProxyConfigDataFromFile(path string) proxyConfigData {
	data, err := os.ReadFile(path)
	if err != nil {
		return proxyConfigData{}
	}
	var p proxyConfigData
	if err := json.Unmarshal(data, &p); err != nil {
		return proxyConfigData{}
	}
	return p
}

// saveProxyConfigToFile 将代理配置持久化到文件
func saveProxyConfigToFile(path string, p proxyConfigData) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// getTCPProxy 线程安全地读取当前代理 URL
func (a *App) getTCPProxy() string {
	a.proxyMu.RLock()
	defer a.proxyMu.RUnlock()
	return a.cfg.TCPProxy
}

// setTCPProxy 线程安全地更新代理 URL，并重新创建 QR client
func (a *App) setTCPProxy(proxyURL string) {
	a.proxyMu.Lock()
	defer a.proxyMu.Unlock()
	a.cfg.TCPProxy = proxyURL
	a.qr = qr.NewClient(a.cfg.RequestTimeout, proxyURL)
	log.Printf("[proxy] 代理已切换: %s", proxyURL)
}

// parseProxyURL 将代理 URL 拆解为结构化数据
func parseProxyURL(url string) proxyConfigData {
	if url == "" {
		return proxyConfigData{}
	}
	var scheme, rest string
	for _, s := range []string{"socks5://"} {
		if len(url) > len(s) && url[:len(s)] == s {
			scheme = url[:len(s)-3]
			rest = url[len(s):]
			break
		}
	}
	if rest == "" {
		return proxyConfigData{}
	}
	atIdx := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '@' {
			atIdx = i
		}
	}
	var user, pass, hostPort string
	if atIdx > 0 {
		cred := rest[:atIdx]
		hostPort = rest[atIdx+1:]
		for i := 0; i < len(cred); i++ {
			if cred[i] == ':' {
				user = cred[:i]
				pass = cred[i+1:]
				break
			}
		}
		if user == "" {
			user = cred
		}
	} else {
		hostPort = rest
	}
	var host, port string
	for i := len(hostPort) - 1; i >= 0; i-- {
		if hostPort[i] == ':' {
			host = hostPort[:i]
			port = hostPort[i+1:]
			break
		}
	}
	return proxyConfigData{
		Scheme: scheme,
		Host:   host,
		Port:   port,
		User:   user,
		Pass:   pass,
	}
}

// handleProxyConfig 处理 GET/POST /api/proxy
func (a *App) handleProxyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		current := a.getTCPProxy()
		p := parseProxyURL(current)
		hasPass := p.Pass != ""
		maskedURL := current
		if hasPass {
			maskedURL = fmt.Sprintf("%s://%s:***@%s:%s", p.Scheme, p.User, p.Host, p.Port)
		}
		resp := map[string]interface{}{
			"code": 0,
			"msg":  "success",
			"data": map[string]interface{}{
				"scheme":    p.Scheme,
				"host":      p.Host,
				"port":      p.Port,
				"user":      p.User,
				"has_pass":  hasPass,
				"proxy_url": maskedURL,
			},
		}
		json.NewEncoder(w).Encode(resp)

	case http.MethodPost:
		var req proxyConfigData
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 400,
				"msg":  "请求格式错误: " + err.Error(),
			})
			return
		}

		// 密码保留逻辑：当前端传来 user 但 pass 为空时，
		// 依次从运行时代理和持久化文件中恢复密码
		if req.Pass == "" && req.User != "" {
			// 1. 先从当前运行时代理恢复
			old := parseProxyURL(a.getTCPProxy())
			if old.User == req.User && old.Pass != "" {
				req.Pass = old.Pass
			}
			// 2. 运行时没有，从持久化文件恢复
			if req.Pass == "" {
				persisted := loadProxyConfigDataFromFile(a.proxyConfigPath())
				if persisted.User == req.User && persisted.Pass != "" {
					req.Pass = persisted.Pass
				}
			}
		}

		proxyURL := req.ToURL()

		// 校验
		if proxyURL != "" {
			if req.Scheme != "socks5" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code": 400,
					"msg":  "代理类型必须是 socks5",
				})
				return
			}
			if req.Host == "" || req.Port == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code": 400,
					"msg":  "代理地址和端口不能为空",
				})
				return
			}
			// 校验端口范围
			if port, err := strconv.Atoi(req.Port); err != nil || port < 1 || port > 65535 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code": 400,
					"msg":  "端口必须是 1-65535 的数字",
				})
				return
			}
		}

		// 应用代理
		a.setTCPProxy(proxyURL)

		// 持久化：无代理时不覆盖文件，保留上次 SOCKS5 配置以便密码恢复
		if proxyURL != "" {
			if err := saveProxyConfigToFile(a.proxyConfigPath(), req); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code": 0,
					"msg":  "代理已生效，但持久化失败: " + err.Error(),
					"data": map[string]interface{}{
						"proxy_url": proxyURL,
					},
				})
				return
			}
		}

		displayURL := proxyURL
		if displayURL == "" {
			displayURL = "无代理（直连）"
		} else if req.User != "" && req.Pass != "" {
			displayURL = fmt.Sprintf("%s://%s:***@%s:%s", req.Scheme, req.User, req.Host, req.Port)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "保存成功，已生效",
			"data": map[string]interface{}{
				"proxy_url": displayURL,
			},
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 405,
			"msg":  "method not allowed",
		})
	}
}

// handleProxyTest 测试代理连接
func (a *App) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 405,
			"msg":  "method not allowed",
		})
		return
	}

	var req proxyConfigData
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 400,
			"msg":  "请求格式错误: " + err.Error(),
		})
		return
	}

	// 密码保留（与 handleProxyConfig 同逻辑）
	if req.Pass == "" && req.User != "" {
		old := parseProxyURL(a.getTCPProxy())
		if old.User == req.User && old.Pass != "" {
			req.Pass = old.Pass
		}
		if req.Pass == "" {
			persisted := loadProxyConfigDataFromFile(a.proxyConfigPath())
			if persisted.User == req.User && persisted.Pass != "" {
				req.Pass = persisted.Pass
			}
		}
	}

	proxyURL := req.ToURL()

	testTimeout := 8 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// 无代理时测试直连
	if proxyURL == "" {
		conn, err := protocol.DialTCP(ctx, "open.weixin.qq.com", 443, testTimeout, "", false)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 500,
				"msg":  "直连失败（无法访问微信服务器）: " + err.Error(),
			})
			return
		}
		conn.Close()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "直连成功（无代理），可访问微信服务器",
		})
		return
	}

	// 校验代理配置
	if req.Scheme != "socks5" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 400,
			"msg":  "代理类型必须是 socks5",
		})
		return
	}
	if req.Host == "" || req.Port == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 400,
			"msg":  "请填写代理类型、地址和端口",
		})
		return
	}

	conn, err := protocol.DialTCP(ctx, "open.weixin.qq.com", 443, testTimeout, proxyURL, false)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 500,
			"msg":  "代理连接失败: " + err.Error(),
		})
		return
	}
	conn.Close()

	displayURL := proxyURL
	if req.User != "" && req.Pass != "" {
		displayURL = fmt.Sprintf("%s://%s:***@%s:%s", req.Scheme, req.User, req.Host, req.Port)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0,
		"msg":  fmt.Sprintf("代理连接成功 (%s)", displayURL),
	})
}

// proxyConfigHTML 是注入到首页的代理配置面板（响应式，复用 configPanelCSS）
const proxyConfigHTML = `<div class="cfg-panel" id="proxy-section">
<h3>代理配置</h3>
<div class="cfg-row">
  <select class="cfg-select" id="px-scheme" onchange="toggleProxyFields()">
    <option value="">无代理（直连）</option>
    <option value="socks5">SOCKS5</option>
  </select>
</div>
<div class="cfg-row" id="px-fields-row">
  <input class="cfg-input" id="px-host" placeholder="代理地址" style="flex:1.5">
  <input class="cfg-port" id="px-port" placeholder="端口">
</div>
<div class="cfg-row" id="px-auth-row">
  <input class="cfg-input" id="px-user" placeholder="用户名（可选）">
  <input class="cfg-input" id="px-pass" type="password" placeholder="密码（可选）">
</div>
<div class="cfg-row cfg-row-btns">
  <button class="cfg-btn cfg-btn-primary" onclick="saveProxy()">保存并生效</button>
  <button class="cfg-btn cfg-btn-secondary" onclick="testProxy()">测试连接</button>
</div>
<div class="cfg-status" id="px-status"></div>
<div class="cfg-hint">当前生效: <span class="cfg-current" id="px-current"></span></div>
</div>
<script>
// 根据下拉框选择，显示/隐藏代理地址、端口、认证字段
// 注意：只隐藏 px-fields-row 和 px-auth-row，不动下拉框所在的行
function toggleProxyFields(){
  var scheme=document.getElementById('px-scheme').value;
  var show=scheme!=='';
  var fieldsRow=document.getElementById('px-fields-row');
  var authRow=document.getElementById('px-auth-row');
  if(fieldsRow) fieldsRow.style.display=show?'':'none';
  if(authRow) authRow.style.display=show?'':'none';
}

function loadProxy(){
  fetch('/api/proxy').then(r=>r.json()).then(d=>{
    if(d.code===0&&d.data){
      var p=d.data;
      document.getElementById('px-scheme').value=p.scheme||'';
      document.getElementById('px-host').value=p.host||'';
      document.getElementById('px-port').value=p.port||'';
      document.getElementById('px-user').value=p.user||'';
      // 不回填密码（安全考虑），但有密码时显示提示
      var passEl=document.getElementById('px-pass');
      passEl.value='';
      passEl.placeholder=p.has_pass?'密码已保存（不改请留空）':'密码（可选）';
      document.getElementById('px-current').textContent=p.proxy_url||'无代理（直连）';
      toggleProxyFields();
    }
  });
}

function saveProxy(){
  var data={
    scheme:document.getElementById('px-scheme').value,
    host:document.getElementById('px-host').value,
    port:document.getElementById('px-port').value,
    user:document.getElementById('px-user').value,
    pass:document.getElementById('px-pass').value
  };
  var s=document.getElementById('px-status');
  s.textContent='保存中...';s.style.color='#667';
  fetch('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(r=>r.json()).then(d=>{
      var s=document.getElementById('px-status');
      if(d.code===0){
        s.style.color='green';s.textContent='\u2713 '+d.msg;
        document.getElementById('px-current').textContent=d.data.proxy_url||'无代理（直连）';
        // 保存成功后清空密码框，更新 placeholder
        var passEl=document.getElementById('px-pass');
        passEl.value='';
        if(data.user) passEl.placeholder='密码已保存（不改请留空）';
      } else {
        s.style.color='red';s.textContent='\u2717 '+d.msg;
      }
    }).catch(e=>{
      var s=document.getElementById('px-status');
      s.style.color='red';s.textContent='\u2717 请求失败: '+e;
    });
}

function testProxy(){
  var data={
    scheme:document.getElementById('px-scheme').value,
    host:document.getElementById('px-host').value,
    port:document.getElementById('px-port').value,
    user:document.getElementById('px-user').value,
    pass:document.getElementById('px-pass').value
  };
  // 无代理时直接测试直连
  if(!data.scheme){
    var s=document.getElementById('px-status');
    s.textContent='测试直连中...';s.style.color='#667';
    fetch('/api/proxy/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
      .then(r=>r.json()).then(d=>{
        var s=document.getElementById('px-status');
        if(d.code===0){s.style.color='green';s.textContent='\u2713 '+d.msg;}
        else{s.style.color='red';s.textContent='\u2717 '+d.msg;}
      }).catch(e=>{
        var s=document.getElementById('px-status');
        s.style.color='red';s.textContent='\u2717 请求失败: '+e;
      });
    return;
  }
  if(!data.host||!data.port){
    var s=document.getElementById('px-status');s.style.color='red';
    s.textContent='\u2717 请填写代理地址和端口';
    return;
  }
  var s=document.getElementById('px-status');
  s.textContent='测试中...';s.style.color='#667';
  fetch('/api/proxy/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(r=>r.json()).then(d=>{
      var s=document.getElementById('px-status');
      if(d.code===0){s.style.color='green';s.textContent='\u2713 '+d.msg;}
      else{s.style.color='red';s.textContent='\u2717 '+d.msg;}
    }).catch(e=>{
      var s=document.getElementById('px-status');
      s.style.color='red';s.textContent='\u2717 请求失败: '+e;
    });
}

// 页面加载时初始化
loadProxy();
</script>`
