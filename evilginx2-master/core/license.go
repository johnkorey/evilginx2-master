package core

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/kgretzky/evilginx2/log"
)

type License struct {
	db          *sql.DB
	instanceID  string
	apiKey      string
	userID      string
	isValid     bool
	lastCheck   time.Time
	subscription *SubscriptionInfo
}

type SubscriptionInfo struct {
	Status       string
	PlanName     string
	MaxInstances int
	MaxSessions  int
	Features     map[string]interface{}
}

func NewLicense(dbHost, dbPort, dbName, dbUser, dbPassword, instanceAPIKey string) (*License, error) {
	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		dbHost, dbPort, dbUser, dbPassword, dbName,
	)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to license database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping license database: %v", err)
	}

	log.Info("license: connected to management platform database")

	lic := &License{
		db:     db,
		apiKey: instanceAPIKey,
	}

	return lic, nil
}

func (l *License) Validate() (bool, error) {
	// Get instance info from database
	var instanceID, userID, status string
	err := l.db.QueryRow(`
		SELECT i.id, i.user_id, i.status 
		FROM instances i
		WHERE i.api_key = $1
	`, l.apiKey).Scan(&instanceID, &userID, &status)

	if err == sql.ErrNoRows {
		return false, fmt.Errorf("instance not found in management platform")
	}
	if err != nil {
		return false, fmt.Errorf("license validation query failed: %v", err)
	}

	l.instanceID = instanceID
	l.userID = userID

	// Check instance status
	if status != "running" && status != "provisioning" {
		return false, fmt.Errorf("instance status is '%s', not running", status)
	}

	// Get user's subscription
	var subscriptionStatus, planName string
	var maxInstances, maxSessions int

	err = l.db.QueryRow(`
		SELECT s.status, sp.display_name, sp.max_instances, sp.max_sessions_per_month
		FROM subscriptions s
		JOIN subscription_plans sp ON s.plan_id = sp.id
		WHERE s.user_id = $1 AND s.status = 'active'
		ORDER BY s.created_at DESC
		LIMIT 1
	`, userID).Scan(&subscriptionStatus, &planName, &maxInstances, &maxSessions)

	if err == sql.ErrNoRows {
		return false, fmt.Errorf("no active subscription found for this instance")
	}
	if err != nil {
		return false, fmt.Errorf("subscription check failed: %v", err)
	}

	l.subscription = &SubscriptionInfo{
		Status:       subscriptionStatus,
		PlanName:     planName,
		MaxInstances: maxInstances,
		MaxSessions:  maxSessions,
	}

	l.isValid = true
	l.lastCheck = time.Now()

	log.Success("license: validated successfully - Plan: %s, Status: %s", planName, subscriptionStatus)

	// Update instance status to 'running' if it was 'provisioning'
	if status == "provisioning" {
		_, err = l.db.Exec(`
			UPDATE instances 
			SET status = 'running', last_heartbeat = CURRENT_TIMESTAMP 
			WHERE id = $1
		`, instanceID)
		if err != nil {
			log.Warning("license: failed to update instance status: %v", err)
		}
	}

	return true, nil
}

func (l *License) SendHeartbeat(resourceUsage map[string]interface{}) error {
	if !l.isValid || l.instanceID == "" {
		return fmt.Errorf("license not validated")
	}

	// Convert resource usage to JSON-like string (simplified)
	health := "healthy"

	_, err := l.db.Exec(`
		UPDATE instances 
		SET last_heartbeat = CURRENT_TIMESTAMP,
		    health_status = $1
		WHERE id = $2
	`, health, l.instanceID)

	if err != nil {
		return fmt.Errorf("heartbeat failed: %v", err)
	}

	return nil
}

func (l *License) IsValid() bool {
	return l.isValid
}

func (l *License) GetSubscriptionInfo() *SubscriptionInfo {
	return l.subscription
}

func (l *License) Close() error {
	if l.db != nil {
		return l.db.Close()
	}
	return nil
}

