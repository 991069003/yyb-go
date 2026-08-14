package httpapi

import (
	"context"
	"database/sql"
	"bytes"
	"io"
	"log"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"yyb_go/internal/protocol"
	"yyb_go/internal/qr"
	"yyb_go/internal/store"

)

type Config struct {
	ResourceRoot   string
	DBFilename     string
	TCPProxy       string
	SessionTTL     time.Duration
	RequestTimeout time.Duration
	AvatarTimeout  time.Duration
	ScanTimeout    time.Duration
	QRSessionTTL   time.Duration
}

type App struct {
	cfg       Config
	resources resources
	db        *store.DB
	pool      *protocol.Pool
	qr        *qr.Client

	mu         sync.Mutex
	qrSessions map[string]*qr.Session
	proxyMu    sync.RWMutex

	// 兼容旧版 14377 站点（wx-login 组件）扫码登录流程：
	// checkqr 轮询到 authorized 后会换取登录缓冲并落库，需保证只落库一次，
	// 因此把最终账号缓存到 compatFinal（按 session id 索引）。
	compatMu    sync.Mutex
	compatFinal map[string]*store.WechatAccount
}

var swaggerDocsHandler = httpSwagger.Handler(
	httpSwagger.URL("/openapi.json"),
	httpSwagger.DocExpansion("list"),
	httpSwagger.DeepLinking(true),
	httpSwagger.DefaultModelsExpandDepth(httpSwagger.ShowModel),
)

func NewApp(cfg Config) (*App, error) {
	if cfg.ResourceRoot == "" {
		cfg.ResourceRoot = filepath.Join(".", "resource")
	}
	if cfg.DBFilename == "" {
		cfg.DBFilename = DefaultDBFilename
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 8 * time.Second
	}
	if cfg.AvatarTimeout == 0 {
		cfg.AvatarTimeout = 10 * time.Second
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * time.Minute
	}
	if cfg.QRSessionTTL == 0 {
		cfg.QRSessionTTL = 5 * time.Minute
	}
	res, err := ensureResources(cfg.ResourceRoot)
	if err != nil {
		return nil, err
	}
	dbPath, err := prepareDBPath(res.DB, cfg.DBFilename)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	poolCfg := protocol.DefaultConfig()
	poolCfg.SessionTTL = cfg.SessionTTL
	poolCfg.ShortlinkTimeout = cfg.RequestTimeout
		// Load persisted proxy config, override command-line if exists
	if persisted := loadProxyConfigFromFile(filepath.Join(cfg.ResourceRoot, proxyConfigFile)); persisted != "" {
		cfg.TCPProxy = persisted
	}
	poolCfg.TCPProxy = cfg.TCPProxy
	// 多 Token：若 api_tokens 表为空，把历史全局 Token 自动播种为第一条记录，
	// 保证已接入的调用方不受影响；随后把启用中的 Token 哈希载入内存缓存。
	if persisted := loadTokenConfigFromFile(filepath.Join(cfg.ResourceRoot, tokenConfigFile)); persisted != "" {
		if err := db.SeedDefaultAPIToken(context.Background(), persisted, hashTokenSecret(persisted)); err != nil {
			log.Printf("[token] 播种默认 Token 失败: %v", err)
		}
	} else if ApiToken != "" {
		if err := db.SeedDefaultAPIToken(context.Background(), ApiToken, hashTokenSecret(ApiToken)); err != nil {
			log.Printf("[token] 播种默认 Token 失败: %v", err)
		}
	}
	loadTokenHashes(db)
	pool := protocol.NewPool(poolCfg, db)
	go sessionCleanupLoop()
	return &App{
		cfg:        cfg,
		resources:  res,
		db:         db,
		pool:       pool,
		qr:         qr.NewClient(cfg.RequestTimeout, cfg.TCPProxy),
		qrSessions: map[string]*qr.Session{},
		compatFinal: map[string]*store.WechatAccount{},
	}, nil
}

func (a *App) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

func (a *App) Handler() http.Handler {
	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.Any("/", gin.WrapF(a.handleIndex))
	router.Any("/scan", gin.WrapF(a.handleScan))
	router.Any("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})
	router.Any("/docs/*path", gin.WrapF(a.handleDocs))
	router.Any("/openapi.json", gin.WrapF(a.handleOpenAPI))
	router.Any("/login", gin.WrapF(handleLogin))
	router.Any("/logout", gin.WrapF(handleLogout))
	router.Any("/health", func(c *gin.Context) {
		writeJSON(c.Writer, http.StatusOK, gin.H{"ok": true})
	})
	router.StaticFS("/static", http.Dir(a.resources.Static))
	router.Any("/qr", gin.WrapF(a.handleQRRoot))
	router.Any("/qr/*path", gin.WrapF(a.handleQR))
	router.Any("/accounts", gin.WrapF(a.handleAccountsRoot))
	router.Any("/accounts/avatar", gin.WrapF(a.handleAccountAvatar))
	router.Any("/accounts/refresh", gin.WrapF(a.handleAccountRefresh))
	router.Any("/accounts/resync", gin.WrapF(a.handleAccountResync))
	router.Any("/wxapp/getCode", gin.WrapF(a.handleGetCode))
	router.Any("/wxapp/getPhoneNumber", gin.WrapF(a.handleGetPhoneNumber))
	router.Any("/wxapp/operateWxData", gin.WrapF(a.handleOperateWXData))
	router.Any("/api/proxy", gin.WrapF(a.handleProxyConfig))
	router.Any("/api/proxy/test", gin.WrapF(a.handleProxyTest))
	router.Any("/api/tokens", gin.WrapF(a.handleTokens))
	router.Any("/api/tokens/:id", gin.WrapF(a.handleTokenByID))
	router.Any("/api/tokens/:id/reset", gin.WrapF(a.handleTokenReset))
	router.GET("/api/token", gin.WrapF(a.handleTokens)) // 兼容旧接口：返回 Token 列表
	router.Any("/api", gin.WrapF(a.handleCompatAPI))     // 兼容 14377 旧版 /api?action=... 接口
	router.NoRoute(func(c *gin.Context) {
		writeError(c.Writer, http.StatusNotFound, "not found")
	})

	return authMiddleware(router)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pageContent, err := readFileOrFallback(filepath.Join(a.resources.Templates, "index.html"), fallbackIndexHTML)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load page")
		return
	}
	const accountAnchor = `<section class="account-band" aria-label="账号队列">`
	configGrid := `<style>
.config-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px;margin:0 0 16px 0}
@media (max-width:780px){.config-grid{grid-template-columns:1fr;gap:12px}}
</style>
<div class="config-grid">` + tokenMgmtHTML + proxyConfigHTML + `</div>`
	if strings.Contains(pageContent, accountAnchor) {
		pageContent = strings.Replace(pageContent, accountAnchor, configGrid+accountAnchor, 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pageContent))
}

func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "scan.html"), fallbackScanHTML)
}

func (a *App) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.Path == "/docs/" {
		http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
		return
	}
	swaggerDocsHandler.ServeHTTP(w, r)
}

func (a *App) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeRawJSON(w, http.StatusOK, openAPISpec)
}

func (a *App) handleQRRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/qr" {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.pruneQR()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+35*time.Second)
	defer cancel()
	img, err := a.qr.GetQRCodeImage(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.mu.Lock()
	a.qrSessions[img.Session.ID] = img.Session
	keep := make(map[string]bool, len(a.qrSessions))
	for sid := range a.qrSessions {
		keep[sid] = true
	}
	a.mu.Unlock()
	path := a.resources.qrPath(img.Session.ID)
	_ = os.WriteFile(path, img.ImageBytes, 0o644)
	a.cleanupQR(keep)
	out := map[string]any{
		"session_id": img.Session.ID,
		"status":     img.Session.Status,
		"image_url":  baseURLFromRequest(r) + "/qr/" + img.Session.ID + "/image",
	}
	if r.URL.Query().Get("as_base64") == "true" {
		out["image_base64"] = qr.DataURIJPEG(img.ImageBytes)
	} else {
		out["image_base64"] = nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/qr/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	sessionID, action := parts[0], parts[1]
	switch action {
	case "image":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		path := a.resources.qrPath(sessionID)
		if _, err := os.Stat(path); err != nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		http.ServeFile(w, r, path)
	case "poll":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.PollQRCode(r.Context(), sess)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		if terminalQR(result.Status) {
			a.dropQRSession(sessionID)
		}
		writeJSON(w, http.StatusOK, result)
	case "confirm":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.GetLoginBuffer(r.Context(), sess)
		if err != nil {
			writeError(w, http.StatusConflict, "buffer not ready: "+err.Error())
			return
		}
		var userInfo map[string]any
		if ui, err := a.qr.LoginBuffers().FetchUserInfo(r.Context(), result.Credentials); err == nil {
			userInfo = ui
		}
		acc, err := a.storeFromScan(r.Context(), result.LoginBuffer, result.Credentials, userInfo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.dropQRSession(sessionID)
		writeJSON(w, http.StatusOK, acc.Public())
	default:
		writeError(w, http.StatusNotFound, "qr session not found")
	}
}

func (a *App) handleAccountsRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts, err := a.db.ListAccounts(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]store.AccountPublic, 0, len(accounts))
		for _, acc := range accounts {
			out = append(out, acc.Public())
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		acc, ok := a.resolveAccountFromQuery(w, r)
		if !ok {
			return
		}
		if err := a.db.DeleteAccount(r.Context(), acc.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": acc.ID, "openid": acc.OpenID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAccountAvatar(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/avatar" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	acc, ok := a.resolveAccountFromQuery(w, r)
	if !ok {
		return
	}
	a.serveAvatar(w, r, acc)
}

func (a *App) handleAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/refresh" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.refreshAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	status := a.refreshLiveness(r.Context(), acc)
	writeJSON(w, http.StatusOK, refreshOut(acc, status))
}

func (a *App) handleAccountResync(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/resync" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.resyncAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	updated, err := a.resyncProfile(r.Context(), acc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated.Public())
}

func (a *App) handleGetCode(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getCode") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetCode)
}

func (a *App) handleGetPhoneNumber(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getPhoneNumber") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetPhoneNumber)
}

func (a *App) handleOperateWXData(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/operateWxData") {
		return
	}
	a.callWXApp(w, r, true, a.invokeOperateWXData)
}

func acceptWXAppRoute(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.URL.Path != path {
		writeError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

type accountRefIn struct {
	Ref string `json:"ref"`
}

type wxappRequest struct {
	Ref     string         `json:"ref"`
	AppID   string         `json:"app_id"`
	Payload map[string]any `json:"payload"`
}

type wxappCall func(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error)

func (a *App) callWXApp(w http.ResponseWriter, r *http.Request, requirePayload bool, call wxappCall) {
	var body wxappRequest
	raw, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) > 0 {
		log.Printf("[callWXApp] from %s | body: %s", r.RemoteAddr, string(raw))
		// Farm5 compat: if request has openid/forceRefresh but no ref/app_id/payload,
		// treat as getCode request - force refresh login_buffer first, then get fresh code
		var aux struct {
			OpenID       string `json:"openid"`
			ForceRefresh bool   `json:"forceRefresh"`
		}
		if err := json.Unmarshal(raw, &aux); err == nil && aux.OpenID != "" && body.Ref == "" && body.AppID == "" && body.Payload == nil {
			acc, ok := a.resolveAccountRef(w, r, aux.OpenID)
			if !ok {
				return
			}
			// Force refresh login_buffer first
			_ = a.db.InvalidateSession(r.Context(), acc.ID, a.getTCPProxy())
			status := a.refreshLiveness(r.Context(), acc)
			if status != "alive" {
				writeError(w, http.StatusConflict, "account login_buffer expired (refresh failed); re-scan required")
				return
			}
			// Re-read fresh account data after refresh
			fresh, err := a.db.GetAccount(r.Context(), acc.ID)
			if err == nil && fresh != nil {
				acc = fresh
			}
			log.Printf("[farm5] got fresh login_buffer, getting code for %s", acc.OpenID)
			// Get a fresh code every time
			result, err := a.pool.GetCode(r.Context(), acc.LoginBuffer, "wx5306c5978fdb76e4", acc.ID, a.getTCPProxy())
			if err != nil {
				writeError(w, http.StatusBadGateway, "getCode failed: "+err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"openid": acc.OpenID, "code": result["code"], "result": result})
			return
		}
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		accounts, err := a.db.ListAccounts(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(accounts) == 1 {
			body.Ref = accounts[0].OpenID
		} else if len(accounts) == 0 {
			writeError(w, http.StatusBadRequest, "no accounts available")
			return
		} else {
			writeError(w, http.StatusBadRequest, "ref is required (multiple accounts found)")
			return
		}
	}
	if body.AppID == "" {
		body.AppID = "wx5306c5978fdb76e4"
	}
	if requirePayload && body.Payload == nil {
		body.Payload = map[string]any{}
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	result, err := a.invokeWXApp(r.Context(), acc, body.AppID, body.Payload, call)
	if err != nil {
		var expired accountExpiredError
		switch {
		case errors.As(err, &expired):
			writeError(w, http.StatusConflict, "account login_buffer expired (refresh failed); re-scan required")
		default:
			writeError(w, http.StatusBadGateway, "call failed: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"openid": acc.OpenID, "result": result})
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (a *App) resolveAccountFromQuery(w http.ResponseWriter, r *http.Request) (*store.WechatAccount, bool) {
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref query param is required")
		return nil, false
	}
	return a.resolveAccountRef(w, r, ref)
}

func (a *App) resolveAccountRef(w http.ResponseWriter, r *http.Request, ref string) (*store.WechatAccount, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}
	acc, err := a.db.ResolveAccount(r.Context(), ref)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "account not found: "+ref)
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}
	return acc, true
}

func (a *App) refreshAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, refreshOut(acc, a.refreshLiveness(r.Context(), acc)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) resyncAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]store.AccountPublic, 0, len(accounts))
	for _, acc := range accounts {
		updated, err := a.resyncProfile(r.Context(), acc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, updated.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) serveAvatar(w http.ResponseWriter, r *http.Request, acc *store.WechatAccount) {
	if acc.Avatar != nil && *acc.Avatar != "" {
		if _, err := os.Stat(*acc.Avatar); err == nil {
			w.Header().Set("Content-Type", "image/jpeg")
			http.ServeFile(w, r, *acc.Avatar)
			return
		}
		if strings.HasPrefix(*acc.Avatar, "http://") || strings.HasPrefix(*acc.Avatar, "https://") {
			http.Redirect(w, r, *acc.Avatar, http.StatusFound)
			return
		}
	}
	writeError(w, http.StatusNotFound, "no avatar")
}

func (a *App) storeFromScan(ctx context.Context, loginBuffer string, creds protocol.LoginBufferCredentials, userInfo map[string]any) (*store.WechatAccount, error) {
	openid := creds.OpenID
	nick := pickNickname(userInfo, creds.Nickname)
	avatar := a.resolveAvatar(ctx, openid, userInfo)
	status := "alive"
	return a.db.UpsertAccount(ctx, openid, loginBuffer, stringPtrMaybe(nick), stringPtrMaybe(nick), stringPtrMaybe(avatar), userInfo, creds.ToMap(), &status)
}

func (a *App) refreshLiveness(ctx context.Context, acc *store.WechatAccount) string {
	if acc.Credentials == nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "unknown")
		return "unknown"
	}
	creds := protocol.CredentialsFromMap(acc.Credentials)
	result, err := a.qr.RefreshLoginBuffer(ctx, creds)
	if err != nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
		return "expired"
	}
	_ = a.db.SetAccountCredential(ctx, acc.ID, result.LoginBuffer, result.Credentials.ToMap())
	_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
	if avatar := a.resolveAvatar(ctx, acc.OpenID, acc.UserInfo); avatar != "" {
		_ = a.db.SetAccountProfile(ctx, acc.ID, acc.Nickname, &avatar, acc.UserInfo)
	}
	return "alive"
}

func (a *App) resyncProfile(ctx context.Context, acc *store.WechatAccount) (*store.WechatAccount, error) {
	nick := pickNickname(acc.UserInfo, deref(acc.Nickname))
	avatar := a.resolveAvatar(ctx, acc.OpenID, acc.UserInfo)
	if avatar == "" {
		avatar = deref(acc.Avatar)
	}
	if err := a.db.SetAccountProfile(ctx, acc.ID, stringPtrMaybe(nick), stringPtrMaybe(avatar), acc.UserInfo); err != nil {
		return nil, err
	}
	return a.db.GetAccount(ctx, acc.ID)
}

type accountExpiredError struct{ openid string }

func (e accountExpiredError) Error() string { return "account expired: " + e.openid }

func (a *App) invokeWXApp(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, call wxappCall) (map[string]any, error) {
	proxy := a.getTCPProxy()
	if _, err := a.db.GetSession(ctx, acc.ID, proxy); err == nil {
		result, err := call(ctx, acc, appID, payload)
		if err == nil {
			return result, nil
		}
		_ = a.db.InvalidateSession(ctx, acc.ID, proxy)
	}
	status := a.refreshLiveness(ctx, acc)
	if status != "alive" {
		return nil, accountExpiredError{openid: acc.OpenID}
	}
	fresh, err := a.db.GetAccount(ctx, acc.ID)
	if err == nil && fresh != nil {
		acc = fresh
	}
	return call(ctx, acc, appID, payload)
}

func (a *App) invokeGetCode(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	return a.pool.GetCode(ctx, acc.LoginBuffer, appID, acc.ID, a.getTCPProxy())
}

func (a *App) invokeGetPhoneNumber(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	return a.pool.GetPhoneNumber(ctx, acc.LoginBuffer, appID, acc.ID, a.getTCPProxy())
}

func (a *App) invokeOperateWXData(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error) {
	return a.pool.OperateWXData(ctx, acc.LoginBuffer, appID, payload, acc.ID, a.getTCPProxy())
}

func refreshOut(acc *store.WechatAccount, status string) map[string]any {
	return map[string]any{"id": acc.ID, "openid": acc.OpenID, "uin": acc.UIN, "nickname": acc.Nickname, "status": status}
}

func pickNickname(userInfo map[string]any, fallback string) string {
	if s := stringFromAny(userInfo["nick_name"]); s != "" {
		return s
	}
	return fallback
}

func pickAvatarURL(userInfo map[string]any) string {
	for _, k := range []string{"head_img_url", "head_url", "headimgurl", "avatar"} {
		if s := stringFromAny(userInfo[k]); s != "" {
			return s
		}
	}
	return ""
}

func (a *App) resolveAvatar(ctx context.Context, openid string, userInfo map[string]any) string {
	u := pickAvatarURL(userInfo)
	if u == "" {
		return ""
	}
	dest := a.resources.avatarPath(openid)
	if downloadAvatar(ctx, u, dest, a.cfg.AvatarTimeout) {
		return dest
	}
	return u
}

func downloadAvatar(ctx context.Context, url, dest string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != 200 || !looksLikeImage(data) {
		return false
	}
	_ = os.MkdirAll(filepath.Dir(dest), 0o755)
	return os.WriteFile(dest, data, 0o644) == nil
}

func looksLikeImage(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	magics := [][]byte{{0xff, 0xd8, 0xff}, {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("GIF87a"), []byte("GIF89a")}
	for _, m := range magics {
		if strings.HasPrefix(string(data), string(m)) {
			return true
		}
	}
	return false
}

func (a *App) getQRSession(id string) *qr.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.qrSessions[id]
}

func (a *App) dropQRSession(id string) {
	a.mu.Lock()
	delete(a.qrSessions, id)
	a.mu.Unlock()
	_ = os.Remove(a.resources.qrPath(id))
}

func (a *App) pruneQR() {
	a.mu.Lock()
	var drop []string
	for sid, sess := range a.qrSessions {
		if sess.Age() > a.cfg.QRSessionTTL {
			drop = append(drop, sid)
		}
	}
	for _, sid := range drop {
		delete(a.qrSessions, sid)
	}
	a.mu.Unlock()
	for _, sid := range drop {
		_ = os.Remove(a.resources.qrPath(sid))
	}
}

func (a *App) cleanupQR(keep map[string]bool) {
	files, _ := filepath.Glob(filepath.Join(a.resources.QR, "*.jpg"))
	for _, f := range files {
		sid := strings.TrimSuffix(filepath.Base(f), ".jpg")
		if !keep[sid] {
			_ = os.Remove(f)
		}
	}
}

func terminalQR(status string) bool {
	return status == "expired" || status == "cancelled" || status == "unknown"
}

type apiEnvelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

// baseURLFromRequest 根据 Nginx 转发头和请求 Host 构建 baseURL，
// 替代 Nginx sub_filter 硬编码方案
func baseURLFromRequest(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	writeRawJSON(w, status, apiEnvelope{
		Code: 0,
		Msg:  "success",
		Data: v,
	})
}

func writeRawJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeRawJSON(w, status, apiEnvelope{
		Code: status,
		Msg:  detail,
		Data: nil,
	})
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}


func readFileOrFallback(filepath, fallback string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fallback, nil
	}
	return string(data), nil
}

func serveFileOrText(w http.ResponseWriter, r *http.Request, path, fallback string) {
	if _, err := os.Stat(path); err == nil {
		http.ServeFile(w, r, path)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fallback))
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringPtrMaybe(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// 兼容接口：旧版 14377 站点（wx-login 组件）通过 Express 反代 /api/proxy 转发到
// 本服务的 /api?action=xxx。所有响应统一为 {code,msg,data}（小写字段），以匹配
// 前端解析逻辑：a.code / a.data.Uuid / a.data.QrBase64 / a.data.acctSectResp 等。
// 前端可能在 query（?action=...&uuid=...&wxid=...）或 JSON body 中携带参数，二者均兼容。
// ---------------------------------------------------------------------------

func (a *App) handleCompatAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action := strings.TrimSpace(q.Get("action"))
	if action == "" {
		var b struct {
			Action string `json:"action"`
		}
		if err := decodeOptionalJSON(r, &b); err == nil {
			action = strings.TrimSpace(b.Action)
		}
	}
	log.Printf("[compat] %s %s action=%q query=%s", r.Method, r.URL.Path, action, r.URL.RawQuery)
	switch action {
	case "getqr":
		a.compatGetQR(w, r)
	case "checkqr":
		a.compatCheckQR(w, r)
	case "jslogin":
		a.compatJSLogin(w, r)
	default:
		writeRawJSON(w, http.StatusOK, map[string]any{
			"code": 1, "msg": "unknown or missing action: " + action, "data": nil,
		})
	}
}

func compatOK(data any) map[string]any {
	return map[string]any{"code": 0, "msg": "success", "data": data}
}

func (a *App) compatGetQR(w http.ResponseWriter, r *http.Request) {
	a.pruneQR()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+35*time.Second)
	defer cancel()
	img, err := a.qr.GetQRCodeImage(ctx)
	if err != nil {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": err.Error(), "data": nil})
		return
	}
	a.mu.Lock()
	a.qrSessions[img.Session.ID] = img.Session
	a.mu.Unlock()
	_ = os.WriteFile(a.resources.qrPath(img.Session.ID), img.ImageBytes, 0o644)
	writeRawJSON(w, http.StatusOK, compatOK(map[string]any{
		"Uuid":     img.Session.WXUUID,
		"uuid":     img.Session.WXUUID,
		"QrBase64": qr.DataURIJPEG(img.ImageBytes),
		"qrBase64": qr.DataURIJPEG(img.ImageBytes),
	}))
}

func (a *App) compatCheckQR(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uuid := strings.TrimSpace(q.Get("uuid"))
	if uuid == "" {
		var b struct {
			UUID string `json:"uuid"`
		}
		_ = decodeOptionalJSON(r, &b)
		uuid = strings.TrimSpace(b.UUID)
	}
	if uuid == "" {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "uuid required", "data": nil})
		return
	}
	// 14377 前端把 uuid 当作扫码会话的 WXUUID 来用，优先按 WXUUID 命中会话
	//（与旧 8080 行为一致），找不到再回退按 session id 查找。
	sess := a.getQRSessionByWX(uuid)
	if sess == nil {
		sess = a.getQRSession(uuid)
	}
	if sess == nil {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "qr session not found", "data": nil})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+10*time.Second)
	defer cancel()
	result, err := a.qr.PollQRCode(ctx, sess)
	if err != nil {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": err.Error(), "data": nil})
		return
	}
	switch result.Status {
	case "pending":
		// 等待扫码 -> 前端 status 0（qr_ready）
		writeRawJSON(w, http.StatusOK, map[string]any{"code": -1, "msg": "waiting", "data": map[string]any{}})
	case "scanned":
		// 已扫码待确认 -> 前端 status 1（confirming）
		writeRawJSON(w, http.StatusOK, map[string]any{"code": -2, "msg": "scanned", "data": map[string]any{}})
	case "authorized", "confirmed":
		acc, info, ferr := a.compatFinalize(ctx, uuid, sess)
		if ferr != nil {
			writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": ferr.Error(), "data": nil})
			return
		}
		avatar := pickAvatarURL(info)
		// 关键：userName/wxid 必须返回 WXUUID（不是 openid），这样 14377 前端
		// 拿到的 wxid 才能与内存里的扫码会话（按 WXUUID 索引）对上，jslogin 才能命中。
		writeRawJSON(w, http.StatusOK, compatOK(map[string]any{
			"wxid":     sess.WXUUID,
			"Wxid":     sess.WXUUID,
			"userName": sess.WXUUID,
			"UserName": sess.WXUUID,
			"nickname": deref(acc.Nickname),
			"nickName": deref(acc.Nickname),
			"avatar":   avatar,
			"Avatar":   avatar,
		}))
	case "cancelled", "expired", "unknown":
		a.dropQRSession(uuid)
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "qr " + result.Status, "data": nil})
	default:
		writeRawJSON(w, http.StatusOK, map[string]any{"code": -1, "msg": "waiting", "data": map[string]any{}})
	}
}

// compatFinalize 在 checkqr 轮询到 authorized 时换取登录缓冲、落库账号，且仅执行一次。
func (a *App) compatFinalize(ctx context.Context, uuid string, sess *qr.Session) (*store.WechatAccount, map[string]any, error) {
	a.compatMu.Lock()
	if acc, ok := a.compatFinal[uuid]; ok {
		a.compatMu.Unlock()
		return acc, nil, nil
	}
	a.compatMu.Unlock()

	res, err := a.qr.GetLoginBuffer(ctx, sess)
	if err != nil {
		return nil, nil, fmt.Errorf("buffer not ready: %w", err)
	}
	var userInfo map[string]any
	if ui, err := a.qr.LoginBuffers().FetchUserInfo(ctx, res.Credentials); err == nil {
		userInfo = ui
	}
	acc, err := a.storeFromScan(ctx, res.LoginBuffer, res.Credentials, userInfo)
	if err != nil {
		return nil, nil, err
	}
	a.compatMu.Lock()
	a.compatFinal[uuid] = acc
	a.compatMu.Unlock()
	return acc, userInfo, nil
}

func (a *App) compatJSLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	wxid := strings.TrimSpace(q.Get("wxid"))
	if wxid == "" {
		var b struct {
			Wxid string `json:"wxid"`
		}
		_ = decodeOptionalJSON(r, &b)
		wxid = strings.TrimSpace(b.Wxid)
	}
	if wxid == "" {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "wxid required", "data": nil})
		return
	}
	// 旧版 14377 前端把 wxid 当成「扫码会话的 WXUUID」：checkqr 授权时返回
	// userName=WXUUID，jslogin 再拿它来匹配内存里的扫码会话（与旧 8080 行为一致），
	// 而不是按 openid 查库。优先按 WXUUID 命中会话。
	sess := a.getQRSessionByWX(wxid)
	if sess == nil {
		sess = a.getQRSession(wxid)
	}
	appID := strings.TrimSpace(r.Header.Get("x-proxy-app-id"))
	if appID == "" {
		appID = "wx5306c5978fdb76e4"
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+10*time.Second)
	defer cancel()

	// compatGetCode 先刷新账号的登录缓冲（与 /wxapp/getCode 经由
	// invokeWXApp -> refreshLiveness 的链路一致），把 OAuth 派生出的原始
	// buffer 重导出为 WMPF 协议可解析的格式，再向农场请求 Code。
	// 直接拿原始 buffer 调 pool.GetCode 会触发 "AppData decrypt/parse failed"。
	compatGetCode := func(acc *store.WechatAccount) {
		// 重新从库读取，确保 Credentials 已加载（refreshLiveness 需要它）。
		if fresh, rerr := a.db.GetAccount(ctx, acc.ID); rerr == nil && fresh != nil {
			acc = fresh
		}
		// 先使缓存会话失效，再刷新登录缓冲（与 invokeWXApp 行为对齐）。
		_ = a.db.InvalidateSession(ctx, acc.ID, a.getTCPProxy())
		status := a.refreshLiveness(ctx, acc)
		if status != "alive" {
			writeRawJSON(w, http.StatusOK, map[string]any{
				"code": 1,
				"msg":  "account login_buffer expired (refresh failed); re-scan required",
				"data": nil,
			})
			return
		}
		// refreshLiveness 已把新 buffer 写库，重新读取拿到最新 LoginBuffer。
		fresh, gerr := a.db.GetAccount(ctx, acc.ID)
		if gerr == nil && fresh != nil {
			acc = fresh
		}
		result, err := a.pool.GetCode(ctx, acc.LoginBuffer, appID, acc.ID, a.getTCPProxy())
		if err != nil {
			writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "getCode failed: " + err.Error(), "data": nil})
			return
		}
		code, _ := result["code"].(string)
		writeRawJSON(w, http.StatusOK, compatOK(map[string]any{"code": code, "Code": code}))
	}

	if sess != nil {
		// compatFinalize 幂等地换取登录缓冲并落库账号（与 checkqr 共用），
		// 返回落库后的账号（含 DB id），sess.LoginBuffer 也会被填充。
		acc, _, ferr := a.compatFinalize(ctx, sess.WXUUID, sess)
		if ferr != nil {
			writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "getLoginBuffer failed: " + ferr.Error(), "data": nil})
			return
		}
		compatGetCode(acc)
		return
	}

	// 兜底：若 wxid 其实是真实 openid，直接按库查找（兼容未来前端改用 openid 的情况）。
	acc, err := a.db.ResolveAccount(ctx, wxid)
	if err != nil {
		writeRawJSON(w, http.StatusOK, map[string]any{"code": 1, "msg": "account not found: " + wxid + " (session expired, please re-scan)", "data": nil})
		return
	}
	compatGetCode(acc)
}

// getQRSessionByWX 按微信扫码会话的 WXUUID 查找内存会话（14377 旧接口用 WXUUID 作为会话标识）。
func (a *App) getQRSessionByWX(wxuuid string) *qr.Session {
	if wxuuid == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.qrSessions {
		if s.WXUUID == wxuuid {
			return s
		}
	}
	return nil
}
