# Unified Authentication & License System - Implementation Plan

**Date:** January 2, 2026  
**Feature:** Single Sign-On + License-Based VPS Limits  
**Status:** 📋 Planning Phase

---

## 🎯 Requirements Summary

### 1. Unified Authentication
- Users created in Management Platform
- **Same credentials** work for:
  - Management Platform login
  - Evilginx2 admin panel access (on their VPS instances)

### 2. Per-User Instances
- Each user deploys Evilginx2 to their own VPS (max 2)
- Each deployment is isolated (user only sees their own data)
- Users cannot see other users' campaigns/sessions

### 3. VPS Limit Enforcement (License System)
- Maximum 2 VPS per user (enforced by license)
- License key tied to user account
- Even if source code copied, won't work on >2 VPS
- License validates against Management Platform

### 4. Embedded Admin UI
- Evilginx2 admin dashboard embedded in Management Platform
- No separate login at port 5555
- Seamless experience within Management Platform

### 5. Admin Privileges
- Management Platform admins automatically have admin access to all Evilginx2 instances
- Can view/manage any user's Evilginx2 instance (for support/monitoring)

---

## 🏗️ Architecture Components

### Component 1: License System
```
User Account (Management Platform)
├─ User ID: abc123
├─ License Key: generated-unique-key-per-user
├─ Max VPS: 2
└─ Active VPS: [vps-1-id, vps-2-id]

Evilginx2 Instance (on VPS)
├─ License Key: (from deployment)
├─ User ID: abc123
├─ Instance ID: vps-1-id
└─ Validates license on startup:
    ├─ Checks against Management Platform API
    ├─ Verifies user_id + license_key match
    ├─ Counts active instances for this user
    └─ Blocks if > 2 instances active
```

### Component 2: Authentication Flow
```
1. User logs into Management Platform
   └─ Email: user@company.com
   └─ Password: UserPass123!

2. User navigates to VPS #1 Evilginx2 Admin
   ├─ Management Platform embeds Evilginx2 UI
   ├─ Passes JWT token to Evilginx2 API
   └─ Evilginx2 validates JWT with Management Platform

3. Evilginx2 API receives request
   ├─ Extracts JWT token
   ├─ Validates against Management Platform /api/auth/verify-token
   ├─ Gets user_id from JWT
   └─ Authorizes request

4. User sees their Evilginx2 admin panel
   └─ Only their campaigns, sessions, lures, etc.
```

### Component 3: Embedded UI
```
Management Platform Frontend
├─ Navigation:
│   ├─ Overview
│   ├─ VPS Servers
│   ├─ Deployments
│   ├─ [NEW] VPS #1 - Evilginx2 Admin ⚡
│   ├─ [NEW] VPS #2 - Evilginx2 Admin ⚡
│   ├─ User Management (admin only)
│   └─ Settings

├─ Evilginx2 Admin Page (per VPS):
│   └─ <iframe> OR API proxy to VPS Evilginx2 admin
│       ├─ Dashboard stats
│       ├─ Phishlets management
│       ├─ Lures management
│       ├─ Sessions (captured credentials)
│       ├─ Configuration
│       └─ Logs
```

---

## 📝 Implementation Steps

### Phase 1: License System (Core Evilginx2)
**Estimated Time:** 4-6 hours

**1.1 Add License Validation to Evilginx2**
```go
// core/license.go
package core

type LicenseManager struct {
    userID          string
    licenseKey      string
    instanceID      string
    managementAPI   string
}

func (lm *LicenseManager) Validate() error {
    // Call Management Platform API
    resp := http.Get(lm.managementAPI + "/api/license/validate", {
        user_id: lm.userID,
        license_key: lm.licenseKey,
        instance_id: lm.instanceID
    })
    
    if resp.StatusCode != 200 {
        return errors.New("License validation failed")
    }
    
    // Check VPS count limit
    if resp.Data.ActiveInstances > 2 {
        return errors.New("License limit exceeded: Maximum 2 VPS instances")
    }
    
    return nil
}
```

**1.2 Add Startup License Check**
```go
// main.go
func main() {
    // ... existing code ...
    
    // ✅ NEW: Validate license on startup
    licenseManager := core.NewLicenseManager(
        config.UserID,
        config.LicenseKey,
        config.InstanceID,
        config.ManagementAPIURL
    )
    
    if err := licenseManager.Validate(); err != nil {
        log.Fatal("License validation failed: %v", err)
        log.Fatal("This instance is not authorized to run")
        return
    }
    
    log.Success("License validated: User %s, Instance %s", config.UserID, config.InstanceID)
    
    // Continue with normal startup...
}
```

**1.3 Periodic License Revalidation**
```go
// Revalidate every hour to prevent unauthorized copies
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        if err := licenseManager.Validate(); err != nil {
            log.Fatal("License validation failed: %v", err)
            os.Exit(1)
        }
    }
}()
```

---

### Phase 2: Management Platform License API
**Estimated Time:** 2-3 hours

**2.1 Create License Endpoints**
```javascript
// backend/routes/license.js
const express = require('express');
const router = express.Router();
const pool = require('../db');
const crypto = require('crypto');

// POST /api/license/validate - Validate Evilginx2 instance license
router.post('/validate', async (req, res) => {
    try {
        const { user_id, license_key, instance_id } = req.body;
        
        // Verify user exists and license key matches
        const userResult = await pool.query(
            'SELECT api_key, status FROM users WHERE id = ?',
            [user_id]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid user' });
        }
        
        const user = userResult.rows[0];
        
        if (user.status !== 'active') {
            return res.status(403).json({ success: false, message: 'User account not active' });
        }
        
        // Verify license key (api_key serves as license key)
        if (user.api_key !== license_key) {
            return res.status(401).json({ success: false, message: 'Invalid license key' });
        }
        
        // Count active VPS instances for this user
        const vpsResult = await pool.query(
            `SELECT COUNT(*) as count FROM instances 
             WHERE user_id = ? AND status IN ('running', 'provisioning')`,
            [user_id]
        );
        
        const activeCount = parseInt(vpsResult.rows[0].count);
        
        // Enforce 2 VPS limit
        if (activeCount > 2) {
            return res.status(403).json({ 
                success: false, 
                message: 'License limit exceeded: Maximum 2 VPS instances allowed' 
            });
        }
        
        // Update instance heartbeat
        await pool.query(
            'UPDATE instances SET last_heartbeat = datetime("now") WHERE id = ?',
            [instance_id]
        );
        
        res.json({
            success: true,
            data: {
                user_id: user_id,
                max_instances: 2,
                active_instances: activeCount,
                licensed: true
            }
        });
        
    } catch (error) {
        console.error('License validation error:', error);
        res.status(500).json({ success: false, message: 'License validation failed' });
    }
});

module.exports = router;
```

**2.2 Generate License Key on User Creation**
```javascript
// backend/routes/users.js - Update createUser function
// The api_key already generated serves as the license key!
// Just need to pass it during deployment
```

---

### Phase 3: Unified Authentication for Evilginx2 Admin
**Estimated Time:** 4-5 hours

**3.1 Add JWT Authentication to Evilginx2**
```go
// core/admin_api.go - Add JWT validation

import (
    "github.com/dgrijalva/jwt-go"
)

func (api *AdminAPI) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        // ✅ NEW: Check JWT token from Management Platform
        authHeader := r.Header.Get("Authorization")
        if strings.HasPrefix(authHeader, "Bearer ") {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            
            // Validate JWT against Management Platform
            userID, err := api.validateJWTWithManagementPlatform(token)
            if err == nil {
                // Check if this user owns this instance
                if api.instanceUserID == userID || api.isManagementPlatformAdmin(token) {
                    next.ServeHTTP(w, r)
                    return
                }
            }
        }

        // Check API key in header (legacy/fallback)
        apiKey := r.Header.Get("X-API-Key")
        if apiKey != "" && subtle.ConstantTimeCompare([]byte(apiKey), []byte(api.apiKey)) == 1 {
            next.ServeHTTP(w, r)
            return
        }

        // Check session cookie (legacy/fallback)
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

func (api *AdminAPI) validateJWTWithManagementPlatform(token string) (string, error) {
    // Call Management Platform API to validate token
    req, _ := http.NewRequest("POST", api.managementPlatformURL + "/api/auth/verify-token", nil)
    req.Header.Set("Authorization", "Bearer " + token)
    
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil || resp.StatusCode != 200 {
        return "", errors.New("Invalid token")
    }
    
    var result struct {
        Success bool `json:"success"`
        Data struct {
            UserID string `json:"userId"`
            Email  string `json:"email"`
        } `json:"data"`
    }
    
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Data.UserID, nil
}
```

**3.2 Store Instance Owner in Config**
```go
// core/config.go - Add instance owner tracking
type Config struct {
    // ... existing fields ...
    InstanceUserID         string  // User who owns this instance
    InstanceLicenseKey     string  // License key for this instance
    ManagementPlatformURL  string  // URL to validate against
}
```

---

### Phase 4: Embed Evilginx2 Admin UI
**Estimated Time:** 3-4 hours

**4.1 Add Evilginx2 Admin Pages to Management Platform**
```html
<!-- frontend/index.html -->

<!-- Evilginx2 Admin Page (Per VPS Instance) -->
<div id="page-evilginx-{vps_id}" class="page">
    <div class="page-header">
        <div>
            <h1>Evilginx2 Admin - {VPS_NAME}</h1>
            <p>Manage phishing campaigns on {VPS_IP}</p>
        </div>
        <div class="header-actions">
            <span class="badge badge-success">Connected</span>
            <button class="btn btn-secondary" onclick="app.refreshEvilginxData('{vps_id}')">
                🔄 Refresh
            </button>
        </div>
    </div>
    
    <!-- Dashboard Stats -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-icon green">📊</div>
            <div class="stat-info">
                <span class="stat-value" id="evilginx-{vps_id}-sessions">0</span>
                <span class="stat-label">Captured Sessions</span>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon blue">🎯</div>
            <div class="stat-info">
                <span class="stat-value" id="evilginx-{vps_id}-phishlets">0</span>
                <span class="stat-label">Active Phishlets</span>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon purple">🔗</div>
            <div class="stat-info">
                <span class="stat-value" id="evilginx-{vps_id}-lures">0</span>
                <span class="stat-label">Active Lures</span>
            </div>
        </div>
    </div>
    
    <!-- Tabs for different sections -->
    <div class="tabs">
        <button class="tab active" data-tab="phishlets">Phishlets</button>
        <button class="tab" data-tab="lures">Lures</button>
        <button class="tab" data-tab="sessions">Sessions</button>
        <button class="tab" data-tab="config">Configuration</button>
    </div>
    
    <!-- Tab Content -->
    <div id="evilginx-content-{vps_id}">
        <!-- Dynamically loaded based on tab -->
    </div>
</div>
```

**4.2 Add API Proxy in Management Platform**
```javascript
// backend/routes/evilginx-proxy.js
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const axios = require('axios');
const pool = require('../db');

// Middleware: Verify user owns the VPS instance
const verifyVPSOwnership = async (req, res, next) => {
    const { vpsId } = req.params;
    const userId = req.user.id;
    
    const result = await pool.query(
        'SELECT * FROM vps_instances WHERE id = ? AND user_id = ?',
        [vpsId, userId]
    );
    
    if (result.rows.length === 0 && !req.user.metadata?.role === 'admin') {
        return res.status(404).json({ success: false, message: 'VPS not found' });
    }
    
    req.vps = result.rows[0];
    next();
};

// Proxy all Evilginx2 admin API requests
router.all('/:vpsId/*', authenticate, verifyVPSOwnership, async (req, res) => {
    try {
        const { vpsId } = req.params;
        const path = req.params[0]; // Everything after /:vpsId/
        
        // Construct URL to user's Evilginx2 instance
        const evilginxURL = `http://${req.vps.server_ip}:5555/api/${path}`;
        
        // Forward request with user's JWT
        const response = await axios({
            method: req.method,
            url: evilginxURL,
            headers: {
                'Authorization': req.headers.authorization,
                'Content-Type': 'application/json'
            },
            data: req.body,
            timeout: 10000
        });
        
        res.json(response.data);
        
    } catch (error) {
        console.error('Evilginx proxy error:', error.message);
        res.status(error.response?.status || 500).json({
            success: false,
            message: error.message || 'Failed to connect to Evilginx2 instance'
        });
    }
});

module.exports = router;
```

---

### Phase 5: Dynamic Navigation
**Estimated Time:** 2-3 hours

**5.1 Generate Evilginx2 Menu Items Per VPS**
```javascript
// frontend/app.js

async loadUserVPSInstances() {
    try {
        const data = await this.apiRequest('/vps');
        this.vpsList = data.data;
        
        // Add navigation items for each VPS
        const navMenu = document.querySelector('.nav-menu');
        
        // Remove old Evilginx2 nav items
        document.querySelectorAll('.nav-item[data-evilginx-vps]').forEach(el => el.remove());
        
        // Add new items for each VPS
        data.data.forEach(vps => {
            if (vps.status === 'running' && vps.is_deployed) {
                const navItem = document.createElement('li');
                navItem.className = 'nav-item';
                navItem.dataset.page = `evilginx-${vps.id}`;
                navItem.dataset.evilginxVps = vps.id;
                navItem.innerHTML = `
                    <svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                    <span>⚡ ${vps.instance_name}</span>
                `;
                navItem.addEventListener('click', () => this.loadEvilginxAdmin(vps.id));
                
                // Insert before Settings
                const settingsItem = navMenu.querySelector('[data-page="settings"]');
                navMenu.insertBefore(navItem, settingsItem);
            }
        });
        
    } catch (error) {
        console.error('Failed to load VPS instances:', error);
    }
}
```

---

### Phase 6: Deployment with License
**Estimated Time:** 2-3 hours

**6.1 Update Deployment Script**
```javascript
// backend/services/ssh.js - Update deploy() function

async deploy(vpsId, deploymentId) {
    // ... existing deployment code ...
    
    // Get user and license info
    const vps = await this.getVPS(vpsId);
    const user = await this.getUser(vps.user_id);
    
    // Create config file with license info
    const configContent = `
user_id: ${user.id}
license_key: ${user.api_key}
instance_id: ${vps.id}
management_platform_url: ${process.env.MANAGEMENT_PLATFORM_URL || 'http://localhost:3000'}
    `;
    
    // Upload config to VPS
    await this.exec(vpsId, `cat > /opt/evilginx/license.conf << 'EOF'
${configContent}
EOF`);
    
    // Install and configure Evilginx2
    // ... rest of deployment ...
}
```

---

## 🔄 Complete User Flow

### Admin Creates User
```
1. Admin logs into Management Platform
2. Goes to "User Management"
3. Clicks "Create User"
4. Fills in:
   ├─ Username: john_doe
   ├─ Email: john@company.com
   ├─ Password: SecurePassword123!
   └─ Full Name: John Doe
5. System generates:
   ├─ User ID: abc123
   ├─ API Key/License: xyz789 (serves as license key)
   └─ Unlimited subscription
6. Admin shares credentials with John
```

### John Adds His VPS
```
1. John logs in: john@company.com / SecurePassword123!
2. Goes to "VPS Servers"
3. Clicks "Add VPS"
4. Enters VPS details:
   ├─ Name: My Production Server
   ├─ Host: 192.168.1.100
   ├─ SSH credentials
   └─ GitHub repo (optional)
5. Clicks "Add VPS" (VPS #1 added)
```

### John Deploys Evilginx2
```
1. On VPS Servers page, clicks "Deploy" on VPS #1
2. Deployment process:
   ├─ Connects to VPS via SSH
   ├─ Clones Evilginx2 from GitHub
   ├─ Creates license.conf with:
   │   ├─ user_id: abc123
   │   ├─ license_key: xyz789
   │   ├─ instance_id: vps-1-id
   │   └─ management_platform_url: http://platform:3000
   ├─ Compiles Evilginx2
   ├─ Installs as system service
   └─ Starts Evilginx2
3. Evilginx2 starts:
   ├─ Reads license.conf
   ├─ Validates against Management Platform API
   ├─ Checks: user abc123 has license xyz789 ✅
   ├─ Checks: Only 1 active instance (< 2 limit) ✅
   └─ Starts successfully
```

### John Accesses Evilginx2 Admin
```
1. In Management Platform, new menu appears:
   ├─ "⚡ My Production Server"
2. John clicks it
3. Management Platform:
   ├─ Loads Evilginx2 admin interface
   ├─ Passes John's JWT token
   └─ Proxies requests to VPS #1 Evilginx2 API
4. Evilginx2 Admin API:
   ├─ Receives JWT token
   ├─ Validates with Management Platform
   ├─ Confirms user abc123 owns this instance
   └─ Returns John's phishing campaigns
5. John sees:
   ├─ His phishlets
   ├─ His lures
   ├─ His captured sessions
   └─ Only HIS data (isolated)
```

### John Tries to Add VPS #3 (License Limit)
```
1. John tries to deploy to VPS #3
2. Deployment starts
3. Evilginx2 on VPS #3 starts
4. License validation:
   ├─ Calls Management Platform API
   ├─ Management Platform checks active instances
   ├─ Finds: John has 2 active instances already
   └─ Returns: 403 License limit exceeded
5. Evilginx2 exits with error:
   "License limit exceeded: Maximum 2 VPS instances"
6. VPS #3 status: "Error - License limit exceeded"
```

### If John Copies Source Code to VPS #4
```
1. John copies Evilginx2 binaries to unauthorized VPS
2. Tries to run without proper license.conf
3. Evilginx2 starts
4. License validation:
   ├─ No license.conf file → FAIL
   OR
   ├─ license.conf present → Validates
   ├─ Management Platform: 2 instances already active
   └─ Returns: 403 License limit exceeded
5. Evilginx2 exits: "License validation failed"
6. Cannot run without valid license
```

---

## 🔐 Security Benefits

### Unified Authentication
- ✅ Single set of credentials per user
- ✅ Centralized user management
- ✅ Easy to revoke access (suspend user)
- ✅ Audit trail in one place

### License Enforcement
- ✅ Hard limit: 2 VPS per user
- ✅ Cannot bypass by copying source
- ✅ Validates on startup and hourly
- ✅ Revocable (suspend user = license invalid)

### Isolation
- ✅ Users only see their own data
- ✅ Cannot access other users' campaigns
- ✅ Separate Evilginx2 instances per user
- ✅ Admin can view all (for support)

---

## 📊 Implementation Complexity

### Phase 1: License System
- **Complexity:** Medium
- **Files:** 3 (license.go, main.go, config.go)
- **Time:** 4-6 hours
- **Risk:** Low (additive, doesn't break existing)

### Phase 2: License API
- **Complexity:** Low
- **Files:** 1 (license.js)
- **Time:** 2-3 hours
- **Risk:** Low (new endpoints)

### Phase 3: JWT Auth in Evilginx2
- **Complexity:** High
- **Files:** 2 (admin_api.go, config.go)
- **Time:** 4-5 hours
- **Risk:** Medium (changes auth flow)

### Phase 4: Embedded UI
- **Complexity:** High
- **Files:** 3 (app.js, index.html, evilginx-proxy.js)
- **Time:** 3-4 hours
- **Risk:** Medium (complex UI changes)

### Phase 5: Dynamic Navigation
- **Complexity:** Medium
- **Files:** 1 (app.js)
- **Time:** 2-3 hours
- **Risk:** Low (UI only)

### Phase 6: Deployment Updates
- **Complexity:** Medium
- **Files:** 2 (ssh.js, vps.js)
- **Time:** 2-3 hours
- **Risk:** Medium (deployment changes)

**Total Estimated Time:** 17-24 hours (2-3 days)

---

## ⚠️ Challenges & Considerations

### 1. Network Communication
- **Issue:** Evilginx2 on VPS needs to reach Management Platform API
- **Solution:** 
  - Management Platform must be publicly accessible OR
  - Use VPN/tunnel between VPS and Management Platform OR
  - Management Platform polling instead of push validation

### 2. JWT Secret Sharing
- **Issue:** Evilginx2 needs JWT secret to validate tokens
- **Solution:** 
  - Option A: Evilginx2 doesn't validate JWT, just forwards to Management Platform
  - Option B: Share JWT public key during deployment (if using RSA tokens)
  - **Recommended:** Option A (simpler, more secure)

### 3. Performance
- **Issue:** Every request goes through Management Platform
- **Solution:**
  - Cache JWT validation results (5-15 minutes)
  - Use Redis for distributed cache
  - Background heartbeat for license check (not per-request)

### 4. Offline Operation
- **Issue:** What if Management Platform is down?
- **Solution:**
  - Grace period (license valid for 24 hours without revalidation)
  - Local cache of last validation
  - Emergency bypass for admins

---

## 🎯 Recommended Implementation Order

### Week 1: Foundation
1. ✅ License API in Management Platform
2. ✅ License validation endpoint
3. ✅ User gets license key (api_key)
4. ✅ Test license validation endpoint

### Week 2: Evilginx2 Integration
1. ✅ Add license validation to Evilginx2
2. ✅ Add JWT authentication support
3. ✅ Update deployment script to include license
4. ✅ Test license enforcement (try 3rd VPS)

### Week 3: UI Integration
1. ✅ Add API proxy in Management Platform
2. ✅ Create embedded Evilginx2 admin pages
3. ✅ Dynamic navigation based on user's VPS
4. ✅ Test end-to-end flow

### Week 4: Polish & Testing
1. ✅ Handle edge cases (offline, errors)
2. ✅ Add loading states and error handling
3. ✅ Comprehensive testing
4. ✅ Documentation

---

## 🤔 Alternative Approaches

### Option A: Full Integration (Recommended Above)
**Pros:**
- Seamless UX
- Single pane of glass
- Centralized control

**Cons:**
- Complex implementation
- Tight coupling
- Network dependency

### Option B: SSO with Redirect
**Pros:**
- Simpler implementation
- Loose coupling
- Each system independent

**Cons:**
- User redirected to different URLs
- Multiple UIs to maintain
- Less seamless experience

### Option C: API Gateway Pattern
**Pros:**
- Clean architecture
- Easy to add more services
- Scalable

**Cons:**
- More infrastructure
- Additional component to manage

---

## ✅ What I Understand

Let me confirm my understanding:

1. **User created in Management Platform** ✅
   - Gets email/password
   - Gets license key (api_key)
   - Max 2 VPS limit

2. **User deploys Evilginx2 to VPS** ✅
   - Deployment includes license configuration
   - Evilginx2 validates license on startup
   - Tied to user account

3. **User accesses Evilginx2 admin** ✅
   - Within Management Platform UI (embedded)
   - Uses same email/password (JWT token)
   - Sees only their own data

4. **License enforcement** ✅
   - Maximum 2 VPS per user
   - Validated on startup and hourly
   - Cannot bypass by copying source code

5. **Admin privileges** ✅
   - Management Platform admins can access any user's Evilginx2 instance
   - For support and monitoring

**Is this correct?** Should I proceed with implementation?

---

**Next Steps if Approved:**
1. Implement license system in Core Evilginx2
2. Add license validation API in Management Platform
3. Create API proxy for embedded access
4. Build embedded Evilginx2 admin UI
5. Update deployment scripts
6. Test end-to-end flow

**Estimated Total Time:** 17-24 hours over 3-4 days


