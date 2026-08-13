package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// tokenConfigFile 存储持久化 API Token 的文件名
const tokenConfigFile = "token_config.json"

// tokenConfigPath 返回 token 配置文件的完整路径
func (a *App) tokenConfigPath() string {
	return filepath.Join(a.cfg.ResourceRoot, tokenConfigFile)
}

// loadTokenConfigFromFile 从文件加载持久化的旧全局 token（用于首次播种）
func loadTokenConfigFromFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var v struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return ""
	}
	return v.Token
}

// tokenIDFromPath 从 /api/tokens/:id 路径中解析数字 id
func tokenIDFromPath(r *http.Request) (int64, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// 例如 "api/tokens/5" -> ["api","tokens","5"]
	if len(parts) < 3 {
		return 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// ---- 多 Token 管理 API ----

func (a *App) handleTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.listTokens(w, r)
	case http.MethodPost:
		a.createToken(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleTokenByID(w http.ResponseWriter, r *http.Request) {
	id, ok := tokenIDFromPath(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.getToken(w, r, id)
	case http.MethodPut:
		a.updateToken(w, r, id)
	case http.MethodDelete:
		a.deleteToken(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleTokenReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, ok := tokenIDFromPath(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	a.resetToken(w, r, id)
}

func (a *App) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.db.ListAPITokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{
			"id":         t.ID,
			"name":       t.Name,
			"secret":     t.Secret,
			"enabled":    t.Enabled,
			"created_at": t.CreatedAt,
			"updated_at": t.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) getToken(w http.ResponseWriter, r *http.Request, id int64) {
	t, err := a.db.GetAPIToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": t.ID, "name": t.Name, "secret": t.Secret, "enabled": t.Enabled,
		"created_at": t.CreatedAt, "updated_at": t.UpdatedAt,
	})
}

func (a *App) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Token-" + time.Now().Format("20060102-150405")
	}
	secret := strings.TrimSpace(req.Secret)
	custom := secret != ""
	if custom && len(secret) < 8 {
		writeError(w, http.StatusBadRequest, "自定义密钥长度不能小于 8 位")
		return
	}
	if !custom {
		secret = generateTokenSecret()
	}
	hash := hashTokenSecret(secret)
	t, err := a.db.CreateAPIToken(r.Context(), name, secret, hash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "密钥冲突，请重试")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tokenCacheAdd(hash)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"secret":     secret, // 仅此一次返回明文
		"enabled":    t.Enabled,
		"created_at": t.CreatedAt,
		"updated_at": t.UpdatedAt,
	})
}

func (a *App) updateToken(w http.ResponseWriter, r *http.Request, id int64) {
	existing, err := a.db.GetAPIToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Secret  *string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	name := existing.Name
	enabled := existing.Enabled
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if name == "" {
		name = existing.Name
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var newSecret, newHash *string
	if req.Secret != nil {
		s := strings.TrimSpace(*req.Secret)
		if s == "" {
			writeError(w, http.StatusBadRequest, "密钥不能为空")
			return
		}
		if len(s) < 8 {
			writeError(w, http.StatusBadRequest, "自定义密钥长度不能小于 8 位")
			return
		}
		h := hashTokenSecret(s)
		newSecret = &s
		newHash = &h
	}
	if t, err := a.db.UpdateAPITokenFull(r.Context(), id, name, enabled, newSecret, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else {
		// 同步内存缓存
		if newHash != nil {
			tokenCacheRemove(existing.SecretHash)
			if enabled {
				tokenCacheAdd(*newHash)
			}
		} else if enabled != existing.Enabled {
			tokenCacheSetEnabled(existing.SecretHash, enabled)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": t.ID, "name": t.Name, "secret": t.Secret, "enabled": t.Enabled,
			"created_at": t.CreatedAt, "updated_at": t.UpdatedAt,
		})
	}
}

func (a *App) resetToken(w http.ResponseWriter, r *http.Request, id int64) {
	existing, err := a.db.GetAPIToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	secret := generateTokenSecret()
	hash := hashTokenSecret(secret)
	if err := a.db.SetAPITokenSecret(r.Context(), id, secret, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tokenCacheRemove(existing.SecretHash)
	if existing.Enabled {
		tokenCacheAdd(hash)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "secret": secret})
}

func (a *App) deleteToken(w http.ResponseWriter, r *http.Request, id int64) {
	existing, err := a.db.GetAPIToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.db.DeleteAPIToken(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tokenCacheRemove(existing.SecretHash)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// configPanelCSS 是注入到首页的共享样式（覆盖 Token 面板和代理面板）
const configPanelCSS = `<style>
.cfg-panel{margin:16px 0;padding:18px;background:#fff;border:1px solid #e4e7ed;border-radius:10px}
.cfg-panel h3{margin:0 0 14px;font-size:16px;font-weight:700}
.cfg-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.cfg-row-btns{display:flex;gap:8px;margin-bottom:0}
.cfg-input{flex:1;min-width:0;padding:9px 12px;border:1px solid #d9e2ef;border-radius:8px;font-size:14px;background:#fff;outline:none;min-height:42px;transition:border-color .15s}
.cfg-input:focus{border-color:#409eff;box-shadow:0 0 0 2px rgba(64,158,255,.12)}
.cfg-select{padding:9px 10px;border:1px solid #d9e2ef;border-radius:8px;font-size:14px;min-height:42px;background:#fff;cursor:pointer}
.cfg-port{width:100px;padding:9px 10px;border:1px solid #d9e2ef;border-radius:8px;font-size:14px;min-height:42px}
.cfg-btn{padding:9px 18px;border:0;border-radius:8px;font-size:14px;cursor:pointer;white-space:nowrap;min-height:42px;transition:background .15s,opacity .15s;font-weight:600}
.cfg-btn-primary{background:#d44a3a;color:#fff}
.cfg-btn-primary:hover{background:#c43f2f}
.cfg-btn-secondary{border:1px solid #d9e2ef;background:#fff;color:#333}
.cfg-btn-secondary:hover{background:#f5f5f5}
.cfg-btn:disabled{opacity:.6;cursor:not-allowed}
.cfg-status{font-size:13px;margin-top:10px;min-height:20px}
.cfg-hint{margin:10px 0 0;font-size:13px;color:#667;line-height:1.5}
.cfg-current{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:#555}
@media(max-width:760px){
  .cfg-panel{margin:12px 0;padding:14px}
  .cfg-row{flex-direction:column;width:100%;gap:10px}
  .cfg-input,.cfg-select,.cfg-port{width:100%;flex:none}
  .cfg-port{width:100%}
  .cfg-row-btns{flex-direction:column;width:100%}
  .cfg-row-btns .cfg-btn{width:100%;flex:none}
}
@media(max-width:480px){
  .cfg-panel{padding:12px;border-radius:8px}
  .cfg-panel h3{font-size:15px;margin-bottom:10px}
  .cfg-btn{font-size:13px;padding:10px 14px}
}
</style>`

// tokenMgmtHTML 是注入到首页的多 Token 管理面板（响应式）
const tokenMgmtHTML = configPanelCSS + `
<div class="cfg-panel" id="api-token-section">
<h3>API Token 管理</h3>
<div class="cfg-row">
  <input class="cfg-input" id="tk-name" placeholder="Token 名称（如：服务器A / 张三）">
  <button class="cfg-btn cfg-btn-primary" onclick="tkCreate()">新建 Token</button>
</div>
<div class="cfg-row">
  <input class="cfg-input" id="tk-secret-input" style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" placeholder="自定义密钥（留空则随机生成 64 位）">
</div>
<div class="cfg-status" id="tk-status"></div>
<div id="tk-secret-box" style="display:none;margin:10px 0;padding:12px;background:#f7f8fa;border:1px dashed #d9e2ef;border-radius:8px">
  <div style="font-size:13px;color:#667;margin-bottom:6px">已生成密钥（仅显示一次，请立即复制保存）：</div>
  <div style="display:flex;gap:8px">
    <input class="cfg-input" id="tk-secret" readonly style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
    <button class="cfg-btn cfg-btn-secondary" onclick="tkCopySecret()">复制</button>
  </div>
</div>
<div id="tk-list" style="margin-top:14px"></div>
<p class="cfg-hint">调用 <code>/wxapp/*</code> 接口时需在请求头添加 <code>Authorization: Bearer &lt;token&gt;</code>。删除或禁用后该密钥立即失效。</p>
</div>
<script>
function tkLoad(){
  fetch('/api/tokens').then(r=>r.json()).then(function(d){
    var box=document.getElementById('tk-list');
    if(d.code!==0||!Array.isArray(d.data)||d.data.length===0){
      box.innerHTML='<div style="font-size:13px;color:#889">暂无 Token</div>';return;
    }
    var html='<div style="overflow-x:auto;-webkit-overflow-scrolling:touch"><table style="width:100%;border-collapse:collapse;font-size:13px;min-width:640px">';
    html+='<tr style="color:#667;text-align:left"><th style="padding:6px">名称</th><th style="padding:6px">密钥</th><th style="padding:6px">状态</th><th style="padding:6px">创建时间</th><th style="padding:6px">操作</th></tr>';
    d.data.forEach(function(t){
      var st=t.enabled?'<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:#e6f7e6;color:#2f9a2f;font-size:12px;white-space:nowrap">启用</span>':'<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:#f0f0f0;color:#888;font-size:12px;white-space:nowrap">禁用</span>';
      var time=new Date((t.created_at||0)*1000).toLocaleString();
      html+='<tr style="border-top:1px solid #eef">';
      html+='<td style="padding:6px">'+esc(t.name)+'</td>';
      var hasSecret=!!(t.secret);
      var secretCell=hasSecret
        ? '<span class="tk-secret-mask" style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">••••••••</span><span class="tk-secret-plain" style="display:none;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all">'+esc(t.secret)+'</span>'
        : '<span style="color:#aaa">未记录</span>';
      var secretActions=hasSecret
        ? ' <button class="cfg-btn cfg-btn-secondary" style="padding:2px 8px;min-height:0;font-size:12px" onclick="tkToggleSecret(this)" data-showing="0">显示</button> <button class="cfg-btn cfg-btn-secondary" style="padding:2px 8px;min-height:0;font-size:12px" onclick="tkCopyRowSecret(this)" data-secret="'+esc(t.secret)+'">复制</button>'
        : '';
      html+='<td style="padding:6px;font-size:12px;max-width:260px">'+secretCell+secretActions+'</td>';
      html+='<td style="padding:6px">'+st+'</td>';
      html+='<td style="padding:6px;color:#889">'+time+'</td>';
      html+='<td style="padding:6px;white-space:nowrap">';
      html+='<button class="cfg-btn cfg-btn-secondary" style="padding:4px 10px;min-height:0;font-size:12px" onclick="tkToggle('+t.id+','+t.enabled+')">'+(t.enabled?'禁用':'启用')+'</button> ';
      html+='<button class="cfg-btn cfg-btn-secondary" style="padding:4px 10px;min-height:0;font-size:12px" data-id="'+t.id+'" data-name="'+esc(t.name)+'" onclick="tkRename(this)">改名</button> ';
      html+='<button class="cfg-btn cfg-btn-secondary" style="padding:4px 10px;min-height:0;font-size:12px" onclick="tkSetSecret('+t.id+')">设置密钥</button> ';
      html+='<button class="cfg-btn cfg-btn-secondary" style="padding:4px 10px;min-height:0;font-size:12px" onclick="tkReset('+t.id+')">重置密钥</button> ';
      html+='<button class="cfg-btn cfg-btn-secondary" style="padding:4px 10px;min-height:0;font-size:12px;color:#d44a3a" onclick="tkDelete('+t.id+')">删除</button>';
      html+='</td></tr>';
    });
    html+='</table></div>';
    box.innerHTML=html;
  }).catch(function(e){
    document.getElementById('tk-list').innerHTML='<div style="color:red;font-size:13px">加载失败: '+e+'</div>';
  });
}
function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function tkStatus(msg,color){var s=document.getElementById('tk-status');s.style.color=color||'#667';s.textContent=msg;}
function tkCreate(){
  var name=document.getElementById('tk-name').value.trim();
  var secret=document.getElementById('tk-secret-input').value.trim();
  tkStatus('创建中...');
  var body={name:name};
  if(secret){ body.secret=secret; }
  fetch('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(function(d){
      if(d.code===0){
        tkStatus('✓ 已创建：'+d.data.name,'green');
        document.getElementById('tk-name').value='';
        document.getElementById('tk-secret-input').value='';
        var sb=document.getElementById('tk-secret-box');sb.style.display='block';
        document.getElementById('tk-secret').value=d.data.secret;
        tkLoad();
      } else { tkStatus('✗ '+d.msg,'red'); }
    }).catch(function(e){ tkStatus('✗ 请求失败: '+e,'red'); });
}
function tkSetSecret(id){
  var s=prompt('请输入新的自定义密钥（至少 8 位；留空则取消）');
  if(s===null) return;
  s=s.trim();
  if(s.length<8){ tkStatus('✗ 密钥长度不能小于 8 位','red'); return; }
  fetch('/api/tokens/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:s})})
    .then(r=>r.json()).then(function(d){
      if(d.code===0){ tkStatus('✓ 密钥已设置','green'); tkLoad(); }
      else { tkStatus('✗ '+d.msg,'red'); }
    });
}
function tkCopyText(s){
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(s).then(function(){ tkStatus('✓ 已复制到剪贴板','green'); }, function(){ tkCopyFallback(s); });
  } else {
    tkCopyFallback(s);
  }
}
function tkCopyFallback(s){
  var ta=document.createElement('textarea'); ta.value=s; ta.style.position='fixed'; ta.style.left='-9999px'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
  try{ var ok=document.execCommand('copy'); tkStatus(ok?'✓ 已复制到剪贴板':'✗ 复制失败', ok?'green':'red'); }
  catch(e){ tkStatus('✗ 复制失败','red'); }
  finally{ document.body.removeChild(ta); }
}
function tkCopySecret(){
  tkCopyText(document.getElementById('tk-secret').value);
}
function tkCopyRowSecret(btn){
  var s=btn.getAttribute('data-secret');
  if(!s){ tkStatus('✗ 没有可复制的密钥','red'); return; }
  tkCopyText(s);
}
function tkToggleSecret(btn){
  var td=btn.parentNode;
  var mask=td.querySelector('.tk-secret-mask');
  var plain=td.querySelector('.tk-secret-plain');
  if(!mask||!plain) return;
  var showing=btn.getAttribute('data-showing')==='1';
  if(showing){
    mask.style.display='inline'; plain.style.display='none';
    btn.setAttribute('data-showing','0'); btn.textContent='显示';
  } else {
    mask.style.display='none'; plain.style.display='inline';
    btn.setAttribute('data-showing','1'); btn.textContent='隐藏';
  }
}
function tkToggle(id,enabled){
  fetch('/api/tokens/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})})
    .then(r=>r.json()).then(function(d){
      if(d.code===0){ tkStatus('✓ 已'+(!enabled?'启用':'禁用'),'green'); tkLoad(); }
      else { tkStatus('✗ '+d.msg,'red'); }
    });
}
function tkRename(btn){
  var id=btn.getAttribute('data-id');
  var cur=btn.getAttribute('data-name');
  var n=prompt('修改 Token 名称', cur);
  if(n===null) return;
  n=n.trim(); if(!n){ return; }
  fetch('/api/tokens/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})})
    .then(r=>r.json()).then(function(d){
      if(d.code===0){ tkStatus('✓ 已改名','green'); tkLoad(); }
      else { tkStatus('✗ '+d.msg,'red'); }
    });
}
function tkReset(id){
  if(!confirm('确定要重置该 Token 的密钥吗？旧密钥将立即失效。')) return;
  fetch('/api/tokens/'+id+'/reset',{method:'POST'}).then(r=>r.json()).then(function(d){
    if(d.code===0){
      tkStatus('✓ 密钥已重置','green');
      var sb=document.getElementById('tk-secret-box');sb.style.display='block';
      document.getElementById('tk-secret').value=d.data.secret;
      tkLoad();
    } else { tkStatus('✗ '+d.msg,'red'); }
  });
}
function tkDelete(id){
  if(!confirm('确定删除该 Token？删除后密钥立即失效且不可恢复。')) return;
  fetch('/api/tokens/'+id,{method:'DELETE'}).then(r=>r.json()).then(function(d){
    if(d.code===0){ tkStatus('✓ 已删除','green'); tkLoad(); }
    else { tkStatus('✗ '+d.msg,'red'); }
  });
}
tkLoad();
</script>`
