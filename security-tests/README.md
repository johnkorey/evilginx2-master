# Security Testing - Proof of Concept Scripts

This directory contains proof-of-concept (PoC) scripts demonstrating the security vulnerabilities identified in the authentication systems audit.

⚠️ **WARNING:** These scripts are for authorized security testing only. Use only in controlled environments with proper authorization.

## Overview

| Script | Vulnerability | Severity | System |
|--------|--------------|----------|--------|
| `poc-brute-force.sh` | No rate limiting | CRITICAL | Admin API (Go) |
| `poc-session-leak.go` | Memory leak from sessions | HIGH | Admin API (Go) |
| `poc-csrf.html` | Missing SameSite cookie flag | HIGH | Admin API (Go) |
| `poc-jwt-forge.js` | Weak default JWT secret | CRITICAL | Management Platform (Node.js) |

## Prerequisites

### For Bash Scripts
- `curl` command-line tool
- `openssl` for random generation
- Running Evilginx2 admin API (default: http://localhost:5555)

### For Go Scripts
- Go 1.16 or later
- Running Evilginx2 admin API
- Valid API key

### For Node.js Scripts
- Node.js 14 or later
- npm packages: `jsonwebtoken`, `axios`
- Running management platform API (default: http://localhost:3000)

## Installation

```bash
# Clone repository (if not already)
cd evilginx2-master/security-tests

# Install Node.js dependencies
npm install jsonwebtoken axios

# Make scripts executable
chmod +x poc-brute-force.sh
chmod +x poc-jwt-forge.js
```

## Usage

### 1. Brute Force Attack (No Rate Limiting)

Demonstrates unlimited login attempts against Admin API.

```bash
./poc-brute-force.sh
```

**Expected Output if Vulnerable:**
```
❌ VULNERABILITY CONFIRMED
Completed 100 attempts in 25s
Average: 4.00 requests/second
Finding: NO RATE LIMITING DETECTED
```

**Expected Output if Fixed:**
```
✅ RATE LIMITED after 5 attempts
Response code: 429
```

### 2. Session Memory Leak

Demonstrates memory accumulation from un-cleaned sessions.

```bash
# Compile
go build poc-session-leak.go

# Run (requires valid API key)
./poc-session-leak
```

Before running, edit the file and set your valid API key:
```go
validAPIKey := "YOUR_VALID_API_KEY_HERE"
```

**Expected Output:**
```
==========================================
PoC: Session Memory Leak Demonstration
==========================================
Sessions created: 1000
Time elapsed: 15.2s
Rate: 65.79 sessions/second

❌ VULNERABILITY DETAILS:
Issue: Sessions stored in memory but never cleaned up
Impact: 1000 sessions ≈ 195 KB server memory
Severity: HIGH
```

**Verification:**
```bash
# Monitor server memory during test
watch -n 1 'ps aux | grep evilginx'

# Memory will continuously grow
# Only restart clears sessions
```

### 3. CSRF Attack

Demonstrates Cross-Site Request Forgery due to missing SameSite flag.

**Setup:**
1. Start Evilginx2 admin API
2. Login to admin panel in browser
3. Open `poc-csrf.html` in the same browser

```bash
# Serve the PoC page
python3 -m http.server 8888

# Open in browser where admin is logged in
# Navigate to: http://localhost:8888/poc-csrf.html
```

**Test Steps:**
1. Authenticate to admin panel (http://localhost:5555)
2. In same browser, open PoC page
3. Click attack buttons
4. Check if attacks succeeded (session deleted, config changed, etc.)

**Expected Result if Vulnerable:**
- Attacks succeed (sessions deleted, phishlets disabled, etc.)
- No CSRF token required
- Browser includes session cookie automatically

**Expected Result if Fixed:**
- Attacks fail
- CSRF token required
- Or SameSite=Strict prevents cookie from being sent

### 4. JWT Token Forgery

Demonstrates authentication bypass via weak default JWT secret.

```bash
# Install dependencies
npm install jsonwebtoken axios

# Run PoC
node poc-jwt-forge.js
```

**Expected Output if Vulnerable:**
```
==========================================
PoC: JWT Token Forgery - Weak Default Secret
==========================================

Attack 1: Forging Admin Token
-------------------------------
Forged Admin Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Attack 2: Testing Forged Token
-------------------------------
✅ VULNERABILITY CONFIRMED!
Forged token was accepted by server!

Attack 3: Checking for Default Secret
--------------------------------------
🔓 WEAK SECRET FOUND: "default_secret_change_me"
❌ CRITICAL VULNERABILITY!
```

**Expected Output if Fixed:**
```
Attack 2: Testing Forged Token
-------------------------------
Server response: 401
✅ Token properly rejected (server using strong secret)
```

## Interpreting Results

### Vulnerability Confirmed (❌)
- Issue exists and is exploitable
- Immediate remediation required
- Follow mitigation steps in main audit report

### Vulnerability Fixed (✅)
- Protection is working correctly
- Test passed successfully
- Verify fix persists in production

### Cannot Test (⚠️)
- Server not running
- Network issues
- Configuration problems
- Check setup and retry

## Remediation Testing

After implementing fixes, re-run PoCs to verify:

```bash
# Test all at once
echo "Testing rate limiting..."
./poc-brute-force.sh

echo "Testing session cleanup..."
./poc-session-leak

echo "Testing JWT security..."
node poc-jwt-forge.js

echo "CSRF test requires manual browser testing"
```

## Expected Timeline for Fixes

| Vulnerability | Fix Complexity | Estimated Time |
|--------------|----------------|----------------|
| Rate limiting | Medium | 2-4 hours |
| Session cleanup | Easy | 1-2 hours |
| Cookie security | Easy | 30 minutes |
| JWT secret | Easy | 15 minutes |

## Additional Testing

### Automated Security Scanning

```bash
# OWASP ZAP (API scan)
docker run -t owasp/zap2docker-stable zap-api-scan.py \
  -t http://localhost:5555/api \
  -f openapi

# Nikto (web server scan)
nikto -h http://localhost:5555

# SQLMap (if database endpoints exist)
sqlmap -u "http://localhost:3000/api/sessions" \
  --cookie="session=..." \
  --level=5 --risk=3
```

### Load Testing

```bash
# Apache Bench
ab -n 1000 -c 10 -p login.json -T application/json \
  http://localhost:5555/api/login

# Verify rate limiting triggers correctly
# Verify session cleanup doesn't crash under load
```

### Penetration Testing Checklist

- [ ] Brute force login
- [ ] Session fixation
- [ ] Session hijacking
- [ ] CSRF attacks
- [ ] JWT token manipulation
- [ ] API key enumeration
- [ ] Memory exhaustion
- [ ] Concurrent access issues
- [ ] Race conditions
- [ ] Privilege escalation

## Reporting Issues

If you discover additional vulnerabilities:

1. **DO NOT** disclose publicly
2. Follow responsible disclosure process
3. Contact security team immediately
4. Provide detailed reproduction steps
5. Include PoC code if possible

## References

- Main audit report: `../SECURITY_AUDIT_AUTH.md`
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CWE-285: Improper Authorization
- CWE-307: Improper Restriction of Authentication Attempts
- CWE-352: Cross-Site Request Forgery
- CWE-798: Use of Hard-coded Credentials

## License

These scripts are provided for security testing purposes only.
Use only with proper authorization on systems you own or have permission to test.

---

**Last Updated:** January 2, 2026  
**Audit Version:** 1.0

