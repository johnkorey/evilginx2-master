package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// =====================================================
// License Manager - Validates instance against Management Platform
// =====================================================

type LicenseManager struct {
	UserID                string
	LicenseKey            string
	InstanceID            string
	ManagementPlatformURL string
	Version               string
	configPath            string
	mu                    sync.RWMutex
	lastValidation        time.Time
	validationInterval    time.Duration
	isValid               bool
}

type LicenseValidationRequest struct {
	UserID     string `json:"user_id"`
	LicenseKey string `json:"license_key"`
	InstanceID string `json:"instance_id"`
	Version    string `json:"version"`
}

type LicenseValidationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		UserID          string `json:"user_id"`
		Username        string `json:"username"`
		Email           string `json:"email"`
		InstanceID      string `json:"instance_id"`
		InstanceName    string `json:"instance_name"`
		MaxInstances    int    `json:"max_instances"`
		ActiveInstances int    `json:"active_instances"`
		Licensed        bool   `json:"licensed"`
	} `json:"data"`
}

func NewLicenseManager(configDir string) (*LicenseManager, error) {
	lm := &LicenseManager{
		configPath:         filepath.Join(configDir, "license.conf"),
		validationInterval: 1 * time.Hour,
		isValid:            false,
	}

	// Load license configuration
	if err := lm.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load license configuration: %v", err)
	}

	return lm, nil
}

func (lm *LicenseManager) loadConfig() error {
	// Check if license.conf exists
	if _, err := os.Stat(lm.configPath); os.IsNotExist(err) {
		return fmt.Errorf("license.conf not found at %s\nThis Evilginx2 instance must be deployed through the Management Platform", lm.configPath)
	}

	// Read license.conf
	data, err := ioutil.ReadFile(lm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read license.conf: %v", err)
	}

	// Parse simple key:value format
	lines := bytes.Split(data, []byte("\n"))
	config := make(map[string]string)
	
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) == 2 {
			key := string(bytes.TrimSpace(parts[0]))
			value := string(bytes.TrimSpace(parts[1]))
			config[key] = value
		}
	}

	// Validate required fields
	lm.UserID = config["user_id"]
	lm.LicenseKey = config["license_key"]
	lm.InstanceID = config["instance_id"]
	lm.ManagementPlatformURL = config["management_platform_url"]

	if lm.UserID == "" {
		return fmt.Errorf("license.conf missing required field: user_id")
	}
	if lm.LicenseKey == "" {
		return fmt.Errorf("license.conf missing required field: license_key")
	}
	if lm.InstanceID == "" {
		return fmt.Errorf("license.conf missing required field: instance_id")
	}
	if lm.ManagementPlatformURL == "" {
		return fmt.Errorf("license.conf missing required field: management_platform_url")
	}

	lm.Version = config["version"]
	if lm.Version == "" {
		lm.Version = "3.0.0"
	}

	return nil
}

func (lm *LicenseManager) Validate() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Prepare validation request
	reqData := LicenseValidationRequest{
		UserID:     lm.UserID,
		LicenseKey: lm.LicenseKey,
		InstanceID: lm.InstanceID,
		Version:    lm.Version,
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	// Call Management Platform API
	url := lm.ManagementPlatformURL + "/api/license/validate"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Management Platform at %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var result LicenseValidationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if !result.Success {
		lm.isValid = false
		return fmt.Errorf("license validation failed: %s", result.Message)
	}

	lm.isValid = true
	lm.lastValidation = time.Now()

	log.Success("License validated successfully")
	log.Info("User: %s (%s)", result.Data.Username, result.Data.Email)
	log.Info("Instance: %s", result.Data.InstanceName)
	log.Info("VPS Usage: %d / %d", result.Data.ActiveInstances, result.Data.MaxInstances)

	return nil
}

func (lm *LicenseManager) StartPeriodicValidation() {
	go func() {
		ticker := time.NewTicker(lm.validationInterval)
		defer ticker.Stop()

		for range ticker.C {
			log.Info("Performing periodic license validation...")
			if err := lm.Validate(); err != nil {
				log.Error("License validation failed: %v", err)
				log.Fatal("This instance is no longer licensed to run")
				os.Exit(1)
			}
		}
	}()

	log.Info("Started periodic license validation (every %v)", lm.validationInterval)
}

func (lm *LicenseManager) SendHeartbeat(stats map[string]interface{}) error {
	reqData := map[string]interface{}{
		"instance_id":  lm.InstanceID,
		"license_key":  lm.LicenseKey,
		"stats":        stats,
	}

	jsonData, _ := json.Marshal(reqData)

	url := lm.ManagementPlatformURL + "/api/license/heartbeat"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed: %s", string(body))
	}

	return nil
}

func (lm *LicenseManager) StartHeartbeat() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			stats := map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"uptime":    time.Since(lm.lastValidation).Seconds(),
			}

			if err := lm.SendHeartbeat(stats); err != nil {
				log.Warning("Heartbeat failed: %v", err)
			}
		}
	}()

	log.Info("Started heartbeat (every 5 minutes)")
}

func (lm *LicenseManager) IsValid() bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.isValid
}

func (lm *LicenseManager) GetUserID() string {
	return lm.UserID
}

func (lm *LicenseManager) GetInstanceID() string {
	return lm.InstanceID
}
