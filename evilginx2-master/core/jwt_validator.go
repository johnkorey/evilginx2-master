package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// =====================================================
// JWT Validator - Validates JWT tokens against Management Platform
// =====================================================

type JWTValidator struct {
	managementPlatformURL string
	cache                 map[string]*CachedValidation
	mu                    sync.RWMutex
	cacheDuration         time.Duration
}

type CachedValidation struct {
	UserID    string
	Email     string
	IsAdmin   bool
	ExpiresAt time.Time
}

type JWTVerifyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
	} `json:"data"`
}

func NewJWTValidator(managementPlatformURL string) *JWTValidator {
	jv := &JWTValidator{
		managementPlatformURL: managementPlatformURL,
		cache:                 make(map[string]*CachedValidation),
		cacheDuration:         5 * time.Minute,
	}

	// Start cache cleanup goroutine
	go jv.cleanupCache()

	return jv
}

func (jv *JWTValidator) ValidateToken(token string) (*CachedValidation, error) {
	// Check cache first
	jv.mu.RLock()
	cached, exists := jv.cache[token]
	jv.mu.RUnlock()

	if exists && time.Now().Before(cached.ExpiresAt) {
		return cached, nil
	}

	// Call Management Platform to validate
	url := jv.managementPlatformURL + "/api/auth/verify-token"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Management Platform: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token validation failed: %s", string(body))
	}

	var result JWTVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("invalid token: %s", result.Message)
	}

	// Check if user is admin (by querying user details)
	isAdmin := jv.checkIfAdmin(token)

	// Cache the validation
	validation := &CachedValidation{
		UserID:    result.Data.UserID,
		Email:     result.Data.Email,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(jv.cacheDuration),
	}

	jv.mu.Lock()
	jv.cache[token] = validation
	jv.mu.Unlock()

	return validation, nil
}

func (jv *JWTValidator) checkIfAdmin(token string) bool {
	// Call Management Platform to get full user details
	url := jv.managementPlatformURL + "/api/users/me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"data"`
	}

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &result)

	if result.Data.Metadata != nil {
		if role, ok := result.Data.Metadata["role"].(string); ok {
			return role == "admin"
		}
	}

	return false
}

func (jv *JWTValidator) cleanupCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		jv.mu.Lock()
		now := time.Now()
		for token, validation := range jv.cache {
			if now.After(validation.ExpiresAt) {
				delete(jv.cache, token)
			}
		}
		jv.mu.Unlock()
	}
}

func (lm *LicenseManager) CreateHeartbeatTicker() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			stats := map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			reqData := map[string]interface{}{
				"instance_id": lm.InstanceID,
				"license_key": lm.LicenseKey,
				"stats":       stats,
			}

			jsonData, _ := json.Marshal(reqData)

			url := lm.ManagementPlatformURL + "/api/license/heartbeat"
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				log.Warning("Heartbeat failed: %v", err)
				continue
			}

			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				log.Warning("Heartbeat failed: %v", err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != 200 {
				log.Warning("Heartbeat returned status: %d", resp.StatusCode)
			}
		}
	}()

	log.Info("Started heartbeat to Management Platform (every 5 minutes)")
}

