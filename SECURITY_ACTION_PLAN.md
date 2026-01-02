# Security Remediation - Action Plan Checklist

**Start Date:** January 2, 2026  
**Target Completion:** February 28, 2026  
**Team Lead:** [Assign Name]  
**Status:** 🔴 In Progress

---

## Phase 1: Critical Fixes (Week 1) - DUE: Jan 9

### Priority 1A: Authentication (2 days)
- [ ] **Remove hardcoded credentials** (`management-platform/backend/db.js`)
  - [ ] Generate random admin password
  - [ ] Save to secure file with 0600 permissions
  - [ ] Force password change on first login
  - [ ] Remove test user creation
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** ___ hours

- [ ] **Fix weak JWT secret** (`middleware/auth.js`)
  - [ ] Generate 64-byte random secret
  - [ ] Add startup validation (fail if default)
  - [ ] Update .env file
  - [ ] Restart service
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 0.5 hours

- [ ] **Implement rate limiting** (Both systems)
  - [ ] Admin API login: 5 attempts / 15 min
  - [ ] Management Platform: express-rate-limit
  - [ ] Test with PoC script
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started  
  - [ ] **ETA:** 3 hours

- [ ] **Session cleanup goroutine** (`core/admin_api.go`)
  - [ ] Add cleanupExpiredSessions() function
  - [ ] Start goroutine in NewAdminAPI()
  - [ ] Test memory usage over 24 hours
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 2 hours

### Priority 1B: Injection & Path Traversal (2 days)
- [ ] **Fix command injection** (`routes/vps.js:464-487`)
  - [ ] OPTION 1: Delete /exec endpoint entirely (RECOMMENDED)
  - [ ] OPTION 2: Implement whitelist-only commands
  - [ ] Add audit logging
  - [ ] Test bypass attempts
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 4 hours

- [ ] **Fix path traversal** (`core/admin_api.go:996-1008`)
  - [ ] Add filepath.Clean() validation
  - [ ] Reject ".." in paths
  - [ ] Verify path within redirectors dir
  - [ ] Test with path traversal payloads
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 3 hours

### Priority 1C: Transport Security (1 day)
- [ ] **Enable HTTPS on Admin API** (`core/admin_api.go:244-260`)
  - [ ] Generate self-signed certificate
  - [ ] Configure TLS 1.3
  - [ ] Update ListenAndServe to ListenAndServeTLS
  - [ ] Test HTTPS access
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 4 hours

- [ ] **Fix cookie security** (`core/admin_api.go:320-326`)
  - [ ] Add Secure flag
  - [ ] Add SameSite=Strict
  - [ ] Test CSRF attacks fail
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started
  - [ ] **ETA:** 0.5 hours

### Phase 1 Testing & Deployment
- [ ] **Run all PoC tests**
  - [ ] `poc-brute-force.sh` - Should fail (rate limited)
  - [ ] `poc-session-leak` - No memory growth
  - [ ] `poc-csrf.html` - Attacks blocked
  - [ ] `poc-jwt-forge.js` - Tokens rejected
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started

- [ ] **Deploy to staging**
  - [ ] Backup database
  - [ ] Deploy fixes
  - [ ] Smoke test all features
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started

- [ ] **Deploy to production**
  - [ ] Schedule maintenance window
  - [ ] Notify customers (if needed)
  - [ ] Deploy during low-traffic period
  - [ ] Monitor for 24 hours
  - [ ] **Assigned to:** ___________
  - [ ] **Status:** Not Started

**Phase 1 Progress:** 0 / 11 tasks complete (0%)

---

## Phase 2: High Priority (Weeks 2-3) - DUE: Jan 23

### Authentication Hardening
- [ ] **Account lockout mechanism** (`routes/auth.js`)
  - [ ] Add failed_login_attempts column
  - [ ] Add account_locked_until column
  - [ ] Lock after 5 failed attempts (30 min)
  - [ ] Reset on successful login
  - [ ] **ETA:** 4 hours

- [ ] **Password requirements** (`routes/auth.js:26-28`)
  - [ ] Minimum 12 characters
  - [ ] Require uppercase, lowercase, number, special
  - [ ] Check against common passwords list
  - [ ] **ETA:** 3 hours

- [ ] **JWT refresh tokens**
  - [ ] Short-lived access tokens (15 min)
  - [ ] Long-lived refresh tokens (7 days)
  - [ ] Refresh endpoint
  - [ ] Store refresh tokens in DB
  - [ ] **ETA:** 6 hours

### Cryptography Improvements
- [ ] **Upgrade SSH credential encryption**
  - [ ] Implement AES-256-GCM
  - [ ] Random IV per encryption
  - [ ] Store IV + authTag + ciphertext
  - [ ] Migrate existing credentials
  - [ ] **ETA:** 6 hours

- [ ] **Encrypt captured passwords**
  - [ ] Implement per-user encryption keys
  - [ ] Encrypt before database storage
  - [ ] Add decryption endpoint (requires user password)
  - [ ] **ETA:** 8 hours

### Security Headers & Validation
- [ ] **Add security headers** (Both systems)
  - [ ] Helmet.js (Management Platform)
  - [ ] Manual headers (Core Evilginx)
  - [ ] Test with securityheaders.com
  - [ ] **ETA:** 2 hours

- [ ] **Input sanitization** (All endpoints)
  - [ ] Install validator.js and xss
  - [ ] Sanitize all user inputs
  - [ ] Validate lengths and types
  - [ ] **ETA:** 8 hours

### Audit Logging
- [ ] **Implement audit logging**
  - [ ] Create AuditLogger class
  - [ ] Log authentication events
  - [ ] Log sensitive operations
  - [ ] Log IP address and user agent
  - [ ] **ETA:** 6 hours

- [ ] **Log redaction**
  - [ ] Create SafeLogger class
  - [ ] Redact passwords, keys, tokens
  - [ ] Update all console.log statements
  - [ ] **ETA:** 4 hours

**Phase 2 Progress:** 0 / 9 tasks complete (0%)

---

## Phase 3: Medium Priority (Month 2) - DUE: Feb 28

### Data Protection
- [ ] **Database encryption at rest**
  - [ ] Implement SQLCipher
  - [ ] Generate encryption key
  - [ ] Test backup/restore
  - [ ] **ETA:** 6 hours

- [ ] **Automated backups**
  - [ ] Setup daily backup cron job
  - [ ] Encrypt backups with GPG
  - [ ] Upload to S3/cloud storage
  - [ ] Test restore procedure
  - [ ] **ETA:** 4 hours

- [ ] **Data retention policy**
  - [ ] Auto-delete old sessions (7-30 days)
  - [ ] Archive old audit logs
  - [ ] GDPR compliance review
  - [ ] **ETA:** 4 hours

### API Security
- [ ] **API versioning**
  - [ ] Implement /api/v1/ prefix
  - [ ] Document API changes
  - [ ] Deprecation headers
  - [ ] **ETA:** 6 hours

- [ ] **CORS improvements**
  - [ ] Dynamic origin validation
  - [ ] Environment-based configuration
  - [ ] Preflight caching
  - [ ] **ETA:** 2 hours

- [ ] **Request size limits**
  - [ ] Per-endpoint limits
  - [ ] Request timeouts
  - [ ] Rate limiting per user
  - [ ] **ETA:** 3 hours

### Infrastructure
- [ ] **Secrets management**
  - [ ] Setup AWS Secrets Manager / Vault
  - [ ] Migrate all secrets
  - [ ] Implement rotation
  - [ ] **ETA:** 8 hours

- [ ] **Dependency management**
  - [ ] Setup Dependabot
  - [ ] Run npm audit
  - [ ] Update vulnerable packages
  - [ ] **ETA:** 4 hours

- [ ] **Monitoring & Alerting**
  - [ ] Setup DataDog/New Relic
  - [ ] Alert on security events
  - [ ] Dashboard for metrics
  - [ ] **ETA:** 6 hours

**Phase 3 Progress:** 0 / 9 tasks complete (0%)

---

## Quick Wins (< 1 hour each) - DO NOW

### Immediate Changes (Can be done in parallel)
- [ ] **Stop logging API key** (`core/admin_api.go:252`)
  ```go
  log.Info("admin API key: %s...", api.apiKey[:8])
  ```
  - **Time:** 5 minutes

- [ ] **Add Secure & SameSite flags** (`core/admin_api.go:320`)
  ```go
  Secure: true,
  SameSite: http.SameSiteStrictMode,
  ```
  - **Time:** 5 minutes

- [ ] **Increase bcrypt rounds** (`routes/auth.js`)
  ```javascript
  const passwordHash = await bcrypt.hash(password, 12);  // Was 10
  ```
  - **Time:** 5 minutes

- [ ] **Add helmet** (already installed!)
  ```javascript
  const helmet = require('helmet');
  app.use(helmet());
  ```
  - **Time:** 2 minutes

- [ ] **Change JWT_SECRET**
  ```bash
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  # Update .env
  ```
  - **Time:** 2 minutes

- [ ] **Add .gitignore entries**
  ```
  .env
  .env.*
  *.key
  *.pem
  api_key.txt
  ```
  - **Time:** 2 minutes

**Quick Wins Progress:** 0 / 6 tasks complete (0%)

---

## Testing Checklist

### Automated Tests
- [ ] Run `poc-brute-force.sh` → Should be rate-limited
- [ ] Run `poc-session-leak` → No memory growth
- [ ] Run `poc-jwt-forge.js` → Tokens rejected
- [ ] Open `poc-csrf.html` → Attacks blocked
- [ ] Run `npm audit` → No high/critical vulnerabilities
- [ ] Security headers test → All headers present
- [ ] OWASP ZAP scan → No high/critical findings

### Manual Testing
- [ ] Login with default credentials → Should fail
- [ ] Try path traversal → Should be blocked
- [ ] Try command injection → Should be blocked
- [ ] Test over HTTP → Should redirect to HTTPS
- [ ] Test CSRF attack → Should be blocked
- [ ] Test account lockout → Locks after 5 attempts
- [ ] Test password requirements → Weak passwords rejected

### Penetration Testing
- [ ] Engage external pen test firm
- [ ] Review findings
- [ ] Remediate any new issues
- [ ] Re-test

---

## Daily Standup Agenda

**Time:** 9:00 AM Daily  
**Duration:** 15 minutes  
**Attendees:** Security lead, developers, QA

### Questions:
1. What did you complete yesterday?
2. What are you working on today?
3. Any blockers?
4. Any security concerns discovered?

### Metrics to Track:
- Tasks completed / Total tasks
- Hours spent / Estimated hours
- Issues discovered during testing
- Deployment readiness

---

## Communication Plan

### Internal Communication
- **Daily:** Standup meeting
- **Weekly:** Status report to management
- **Ad-hoc:** Slack #security channel for issues

### External Communication
- **Customer Notification:** [IF BREACH DETECTED]
  - Subject: Security Update
  - Timeline: Within 72 hours of discovery
  - Channel: Email to all users
  
- **Public Disclosure:** [IF REQUIRED]
  - Coordinate with legal team
  - Prepare FAQ
  - Designate spokesperson

---

## Risk Register

### Active Risks During Remediation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Service downtime | Medium | High | Deploy during low traffic, have rollback plan |
| New vulnerabilities introduced | Low | High | Code review all changes, test thoroughly |
| Timeline slip | Medium | Medium | Daily tracking, prioritize critical fixes |
| Resource unavailability | Low | High | Cross-train team members |

---

## Success Metrics

### Phase 1 Success Criteria
- [ ] All critical vulnerabilities patched
- [ ] All PoC exploits fail
- [ ] Zero new security issues introduced
- [ ] Service uptime > 99.5%

### Phase 2 Success Criteria
- [ ] All high vulnerabilities patched
- [ ] Audit logging operational
- [ ] Security headers implemented
- [ ] Account lockout working

### Phase 3 Success Criteria
- [ ] All medium vulnerabilities patched
- [ ] Monitoring operational
- [ ] External pen test passed
- [ ] Compliance requirements met

### Overall Success
- [ ] Zero critical/high vulnerabilities remaining
- [ ] All automated tests passing
- [ ] External pen test shows only low/info findings
- [ ] Team trained on secure coding
- [ ] Incident response plan documented

---

## Rollback Plan

### If Critical Issue Discovered Post-Deployment

1. **Immediate Actions (< 5 minutes)**
   - [ ] Rollback to previous version
   - [ ] Notify security lead
   - [ ] Start incident log

2. **Analysis (< 30 minutes)**
   - [ ] Identify root cause
   - [ ] Assess impact
   - [ ] Check for exploitation

3. **Communication (< 1 hour)**
   - [ ] Notify management
   - [ ] Internal team alert
   - [ ] Prepare customer communication (if needed)

4. **Fix (< 4 hours)**
   - [ ] Develop hotfix
   - [ ] Test in staging
   - [ ] Deploy with approval

---

## Post-Remediation Activities

### Week 1 Post-Deployment
- [ ] Monitor logs for anomalies
- [ ] Check error rates
- [ ] Customer feedback review
- [ ] Performance metrics analysis

### Month 1 Post-Deployment
- [ ] External penetration test
- [ ] Security code review
- [ ] Team retrospective
- [ ] Update documentation

### Ongoing
- [ ] Monthly vulnerability scans
- [ ] Quarterly security reviews
- [ ] Annual penetration tests
- [ ] Continuous training

---

## Budget Tracking

| Item | Estimated | Actual | Status |
|------|-----------|--------|--------|
| Developer time (Phase 1) | $12,000 | $ | |
| Developer time (Phase 2) | $18,000 | $ | |
| Developer time (Phase 3) | $20,000 | $ | |
| Security tools | $5,000 | $ | |
| External pen test | $15,000 | $ | |
| Training | $5,000 | $ | |
| **Total** | **$75,000** | **$** | |

---

## Documentation Updates Required

- [ ] Update README with security considerations
- [ ] Document new environment variables
- [ ] Update deployment guide
- [ ] Create security runbook
- [ ] Document incident response procedures
- [ ] Update API documentation

---

## Sign-offs

### Phase 1 Completion
- [ ] Security Lead: _________________ Date: _______
- [ ] Development Lead: ______________ Date: _______
- [ ] QA Lead: ______________________ Date: _______
- [ ] Management Approval: ___________ Date: _______

### Phase 2 Completion
- [ ] Security Lead: _________________ Date: _______
- [ ] Development Lead: ______________ Date: _______
- [ ] QA Lead: ______________________ Date: _______

### Phase 3 Completion & Final Sign-off
- [ ] Security Lead: _________________ Date: _______
- [ ] Development Lead: ______________ Date: _______
- [ ] QA Lead: ______________________ Date: _______
- [ ] Management Approval: ___________ Date: _______
- [ ] External Auditor: ______________ Date: _______

---

## Notes & Issues Log

### Week 1
```
Date: ___________
Issues:



Decisions:



```

### Week 2
```
Date: ___________
Issues:



Decisions:



```

### Week 3-4
```
Date: ___________
Issues:



Decisions:



```

---

**Document Owner:** Security Lead  
**Last Updated:** January 2, 2026  
**Next Review:** Weekly during remediation  
**Status:** 🔴 In Progress


