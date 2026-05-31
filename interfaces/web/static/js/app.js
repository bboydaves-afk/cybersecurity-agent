/* CyberSecurity Agent — SPA Application */

// ─── State ───
const state = {
    token: localStorage.getItem('hacking_token') || null,
    username: localStorage.getItem('hacking_user') || null,
    currentView: 'dashboard',
    dashboardData: null,
    chatMessages: [],
    chatLoading: false,
};

// ─── API Helper ───
const API = {
    base: '/api',

    async request(path, options = {}) {
        const url = this.base + path;
        const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
        if (state.token) {
            headers['Authorization'] = `Bearer ${state.token}`;
        }
        try {
            const resp = await fetch(url, { ...options, headers });
            if (resp.status === 401) {
                state.token = null;
                localStorage.removeItem('hacking_token');
                renderLogin();
                return null;
            }
            return await resp.json();
        } catch (e) {
            console.error('API Error:', e);
            return { error: e.message };
        }
    },

    get(path) { return this.request(path); },

    post(path, body) {
        return this.request(path, { method: 'POST', body: JSON.stringify(body) });
    },

    patch(path, body) {
        return this.request(path, { method: 'PATCH', body: JSON.stringify(body) });
    },
};

// ─── Router ───
function navigate(view) {
    state.currentView = view;
    document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.view === view);
    });
    document.querySelector('.header-left h2').textContent = getViewTitle(view);
    renderView(view);
}

function getViewTitle(view) {
    const titles = {
        dashboard: 'Dashboard',
        targets: 'Targets & Projects',
        recon: 'Reconnaissance',
        vulnerabilities: 'Vulnerabilities',
        exploits: 'Exploitation',
        web_security: 'Web Security',
        cloud_security: 'Cloud Security',
        compliance: 'Compliance',
        reports: 'Reports',
        chat: 'AI Chat',
    };
    return titles[view] || view;
}

// ─── Render View ───
function renderView(view) {
    const area = document.getElementById('content-area');
    const renderers = {
        dashboard: renderDashboard,
        targets: renderTargets,
        recon: renderRecon,
        vulnerabilities: renderVulnerabilities,
        exploits: renderExploits,
        web_security: renderWebSecurity,
        cloud_security: renderCloudSecurity,
        compliance: renderCompliance,
        reports: renderReports,
        chat: renderChat,
    };
    const fn = renderers[view];
    if (fn) fn(area);
    else area.innerHTML = `<div class="empty-state"><div class="icon">?</div><p>Unknown view</p></div>`;
}

// ─── Helpers ───
function severityBadge(s) {
    return `<span class="severity ${(s||'').toLowerCase()}">${(s||'N/A').toUpperCase()}</span>`;
}

function statusBadge(s) {
    return `<span class="status ${(s||'').toLowerCase()}">${s||'N/A'}</span>`;
}

function timeAgo(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    const now = new Date();
    const diff = Math.floor((now - d) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function showLoading(container) {
    container.innerHTML = '<div class="loading-overlay"><div class="loading-spinner"></div> Loading...</div>';
}

// ─── Dashboard ───
async function renderDashboard(area) {
    showLoading(area);
    const data = await API.get('/dashboard/stats');
    if (!data || data.error) {
        area.innerHTML = `<div class="empty-state"><div class="icon">!</div><p>${data?.error || 'Failed to load'}</p></div>`;
        return;
    }
    state.dashboardData = data;
    const sev = data.findings_by_severity || {};
    const total = data.total_findings || 0;

    let severityBarHtml = '';
    if (total > 0) {
        const segments = ['critical', 'high', 'medium', 'low', 'info'].map(s => {
            const cnt = sev[s] || 0;
            if (cnt === 0) return '';
            const pct = (cnt / total * 100).toFixed(1);
            return `<div class="segment ${s}" style="width:${pct}%">${cnt}</div>`;
        }).join('');
        severityBarHtml = `<div class="severity-bar">${segments}</div>`;
    }

    area.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card accent">
                <div class="stat-icon">&#9881;</div>
                <div class="stat-value">${data.active_projects || 0}</div>
                <div class="stat-label">Active Projects</div>
            </div>
            <div class="stat-card info">
                <div class="stat-icon">&#9678;</div>
                <div class="stat-value">${data.total_targets || 0}</div>
                <div class="stat-label">Targets in Scope</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-icon">&#9888;</div>
                <div class="stat-value">${total}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-icon">&#9889;</div>
                <div class="stat-value">${sev.critical || 0}</div>
                <div class="stat-label">Critical Findings</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Severity Breakdown</h3></div>
            ${severityBarHtml || '<p class="text-dim">No findings yet</p>'}
            <div class="severity-legend">
                <div class="legend-item"><div class="legend-dot" style="background:var(--severity-critical)"></div> Critical (${sev.critical||0})</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--severity-high)"></div> High (${sev.high||0})</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--severity-medium)"></div> Medium (${sev.medium||0})</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--severity-low)"></div> Low (${sev.low||0})</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--severity-info)"></div> Info (${sev.info||0})</div>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <div class="card-header"><h3>Recent Findings</h3></div>
                <table class="data-table">
                    <thead><tr><th>Severity</th><th>Title</th><th>When</th></tr></thead>
                    <tbody>
                        ${(data.recent_findings || []).map(f => `
                            <tr>
                                <td>${severityBadge(f.severity)}</td>
                                <td>${escapeHtml(f.title || '')}</td>
                                <td class="text-dim">${timeAgo(f.created_at)}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="3" class="text-dim">No findings yet</td></tr>'}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-header"><h3>Recent Scans</h3></div>
                <table class="data-table">
                    <thead><tr><th>Type</th><th>Status</th><th>When</th></tr></thead>
                    <tbody>
                        ${(data.recent_scans || []).map(s => `
                            <tr>
                                <td>${escapeHtml(s.scan_type || '')}</td>
                                <td>${statusBadge(s.status)}</td>
                                <td class="text-dim">${timeAgo(s.started_at)}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="3" class="text-dim">No scans yet</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

// ─── Targets ───
async function renderTargets(area) {
    showLoading(area);
    const [projectsData, targetsData] = await Promise.all([
        API.get('/projects'),
        API.get('/targets'),
    ]);

    const projects = projectsData?.projects || [];
    const targets = targetsData?.targets || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>${projects.length} Projects, ${targets.length} Targets</h3>
            <div class="flex gap-8">
                <button class="btn btn-primary" onclick="showNewProjectModal()">+ New Project</button>
                <button class="btn btn-secondary" onclick="showNewTargetModal()">+ Add Target</button>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Projects</h3></div>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Name</th><th>Client</th><th>Type</th><th>Status</th></tr></thead>
                <tbody>
                    ${projects.map(p => `
                        <tr>
                            <td class="mono">${escapeHtml(p.id || '')}</td>
                            <td>${escapeHtml(p.name || '')}</td>
                            <td>${escapeHtml(p.client || '-')}</td>
                            <td>${escapeHtml(p.project_type || '')}</td>
                            <td>${statusBadge(p.status)}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="5" class="text-dim">No projects</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card mt-16">
            <div class="card-header"><h3>Targets</h3></div>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Value</th><th>Type</th><th>In Scope</th></tr></thead>
                <tbody>
                    ${targets.map(t => `
                        <tr>
                            <td class="mono">${escapeHtml(t.id || '')}</td>
                            <td class="text-accent mono">${escapeHtml(t.value || '')}</td>
                            <td>${escapeHtml(t.target_type || '')}</td>
                            <td>${t.in_scope ? '<span class="text-accent">Yes</span>' : '<span class="text-danger">No</span>'}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="4" class="text-dim">No targets</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function showNewProjectModal() {
    showModal('New Project', `
        <div class="form-group">
            <label>Project Name</label>
            <input class="form-input" id="modal-proj-name" placeholder="Internal Pentest Q1">
        </div>
        <div class="form-group">
            <label>Client</label>
            <input class="form-input" id="modal-proj-client" placeholder="Acme Corp">
        </div>
        <div class="form-group">
            <label>Type</label>
            <select class="form-select" id="modal-proj-type">
                <option value="pentest">Penetration Test</option>
                <option value="bug_bounty">Bug Bounty</option>
                <option value="red_team">Red Team</option>
                <option value="ctf">CTF</option>
                <option value="audit">Security Audit</option>
            </select>
        </div>
    `, async () => {
        const name = document.getElementById('modal-proj-name').value;
        const client = document.getElementById('modal-proj-client').value;
        const type = document.getElementById('modal-proj-type').value;
        if (!name) return alert('Name required');
        await API.post('/projects', { name, client, project_type: type });
        hideModal();
        renderTargets(document.getElementById('content-area'));
    });
}

function showNewTargetModal() {
    showModal('Add Target', `
        <div class="form-group">
            <label>Target Value (IP, domain, URL)</label>
            <input class="form-input" id="modal-tgt-value" placeholder="192.168.1.1 or example.com">
        </div>
        <div class="form-group">
            <label>Type</label>
            <select class="form-select" id="modal-tgt-type">
                <option value="host">Host</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="network">Network</option>
                <option value="cloud">Cloud</option>
            </select>
        </div>
        <div class="form-group">
            <label>Project ID</label>
            <input class="form-input" id="modal-tgt-project" placeholder="proj-xxxxx">
        </div>
    `, async () => {
        const value = document.getElementById('modal-tgt-value').value;
        const type = document.getElementById('modal-tgt-type').value;
        const projectId = document.getElementById('modal-tgt-project').value;
        if (!value || !projectId) return alert('Value and Project ID required');
        await API.post('/targets', { value, target_type: type, project_id: projectId });
        hideModal();
        renderTargets(document.getElementById('content-area'));
    });
}

// ─── Recon ───
async function renderRecon(area) {
    showLoading(area);
    const data = await API.get('/scans');
    const scans = data?.scans || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Reconnaissance (${scans.length} scans)</h3>
            <button class="btn btn-primary" onclick="showPortScanModal()">+ Port Scan</button>
        </div>

        <div class="card">
            <div class="card-header"><h3>Scan History</h3></div>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Started</th></tr></thead>
                <tbody>
                    ${scans.map(s => `
                        <tr>
                            <td class="mono">${escapeHtml(s.id || '')}</td>
                            <td>${escapeHtml(s.scan_type || '')}</td>
                            <td>${statusBadge(s.status)}</td>
                            <td class="text-dim">${timeAgo(s.started_at)}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="4" class="text-dim">No scans yet. Run a port scan to get started.</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function showPortScanModal() {
    showModal('Port Scan', `
        <div class="form-group">
            <label>Target</label>
            <input class="form-input" id="modal-scan-target" placeholder="192.168.1.1">
        </div>
        <div class="form-group">
            <label>Ports</label>
            <input class="form-input" id="modal-scan-ports" value="1-1000" placeholder="1-1000 or 80,443,8080">
        </div>
        <div class="form-group">
            <label>Scan Type</label>
            <select class="form-select" id="modal-scan-type">
                <option value="syn">SYN Scan</option>
                <option value="connect">Connect Scan</option>
                <option value="udp">UDP Scan</option>
            </select>
        </div>
    `, async () => {
        const target = document.getElementById('modal-scan-target').value;
        const ports = document.getElementById('modal-scan-ports').value;
        const scanType = document.getElementById('modal-scan-type').value;
        if (!target) return alert('Target required');
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        const result = await API.post('/scans/port-scan', { target, ports, scan_type: scanType });
        renderRecon(area);
    });
}

// ─── Vulnerabilities ───
async function renderVulnerabilities(area) {
    showLoading(area);
    const data = await API.get('/findings');
    const findings = data?.findings || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Findings (${findings.length} total)</h3>
            <div class="flex gap-8">
                <select class="form-select" id="filter-severity" style="width:auto;" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
            </div>
        </div>

        <div class="card">
            <table class="data-table" id="findings-table">
                <thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                    ${findings.map(f => `
                        <tr data-severity="${(f.severity||'').toLowerCase()}">
                            <td>${severityBadge(f.severity)}</td>
                            <td>${escapeHtml(f.title || '')}</td>
                            <td>${statusBadge(f.status)}</td>
                            <td class="text-dim">${timeAgo(f.created_at)}</td>
                            <td><button class="btn btn-sm btn-secondary" onclick="viewFinding('${f.id}')">View</button></td>
                        </tr>
                    `).join('') || '<tr><td colspan="5" class="text-dim">No findings yet</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function filterFindings() {
    const sev = document.getElementById('filter-severity').value;
    document.querySelectorAll('#findings-table tbody tr').forEach(tr => {
        if (!sev || tr.dataset.severity === sev) {
            tr.style.display = '';
        } else {
            tr.style.display = 'none';
        }
    });
}

async function viewFinding(id) {
    const data = await API.get(`/findings/${id}`);
    if (!data || !data.finding) return;
    const f = data.finding;
    showModal(`Finding: ${f.title || id}`, `
        <div class="mb-8">${severityBadge(f.severity)} ${statusBadge(f.status)}</div>
        <div class="form-group">
            <label>Description</label>
            <div class="terminal-output">${escapeHtml(f.description || 'No description')}</div>
        </div>
        <div class="form-group">
            <label>Remediation</label>
            <div style="color:var(--text-secondary);font-size:13px;">${escapeHtml(f.remediation || 'No remediation guidance')}</div>
        </div>
        <div class="form-group">
            <label>Evidence</label>
            <div class="terminal-output">${escapeHtml(f.evidence || 'No evidence recorded')}</div>
        </div>
    `, null);
}

// ─── Exploits ───
async function renderExploits(area) {
    showLoading(area);
    const [exploitData, sessionData] = await Promise.all([
        API.get('/exploits'),
        API.get('/sessions'),
    ]);

    const exploits = exploitData?.exploits || [];
    const sessions = sessionData?.sessions || [];

    area.innerHTML = `
        <div class="grid-2">
            <div class="card">
                <div class="card-header"><h3>Exploit History (${exploits.length})</h3></div>
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Status</th><th>Executed</th></tr></thead>
                    <tbody>
                        ${exploits.map(e => `
                            <tr>
                                <td class="mono">${escapeHtml(e.id || '')}</td>
                                <td>${statusBadge(e.status)}</td>
                                <td class="text-dim">${timeAgo(e.executed_at)}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="3" class="text-dim">No exploits executed</td></tr>'}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-header"><h3>Active Sessions (${sessions.length})</h3></div>
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Created</th></tr></thead>
                    <tbody>
                        ${sessions.map(s => `
                            <tr>
                                <td class="mono">${escapeHtml(s.id || '')}</td>
                                <td class="text-dim">${timeAgo(s.created_at)}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="2" class="text-dim">No active sessions</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

// ─── Web Security ───
async function renderWebSecurity(area) {
    showLoading(area);
    const [endpointData, scanData] = await Promise.all([
        API.get('/web/endpoints'),
        API.get('/web/scans'),
    ]);

    const endpoints = endpointData?.endpoints || [];
    const scans = scanData?.scans || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Web Security</h3>
            <div class="flex gap-8">
                <button class="btn btn-primary" onclick="showHeadersModal()">Analyze Headers</button>
                <button class="btn btn-secondary" onclick="showSslModal()">Test SSL/TLS</button>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <div class="card-header"><h3>Discovered Endpoints (${endpoints.length})</h3></div>
                <table class="data-table">
                    <thead><tr><th>URL</th><th>Status</th></tr></thead>
                    <tbody>
                        ${endpoints.slice(0, 20).map(e => `
                            <tr>
                                <td class="mono text-accent">${escapeHtml(e.url || '')}</td>
                                <td>${e.status_code || '-'}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="2" class="text-dim">No endpoints discovered</td></tr>'}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-header"><h3>Web Scans (${scans.length})</h3></div>
                <table class="data-table">
                    <thead><tr><th>Type</th><th>Status</th><th>When</th></tr></thead>
                    <tbody>
                        ${scans.map(s => `
                            <tr>
                                <td>${escapeHtml(s.scan_type || '')}</td>
                                <td>${statusBadge(s.status)}</td>
                                <td class="text-dim">${timeAgo(s.started_at)}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="3" class="text-dim">No web scans yet</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function showHeadersModal() {
    showModal('Analyze HTTP Headers', `
        <div class="form-group">
            <label>URL</label>
            <input class="form-input" id="modal-header-url" placeholder="https://example.com">
        </div>
    `, async () => {
        const url = document.getElementById('modal-header-url').value;
        if (!url) return alert('URL required');
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        const result = await API.post('/web/headers', { url });
        area.innerHTML = `
            <button class="btn btn-secondary mb-16" onclick="renderWebSecurity(document.getElementById('content-area'))">Back</button>
            <div class="card">
                <div class="card-header"><h3>Header Analysis: ${escapeHtml(url)}</h3><span>Grade: <strong class="text-accent">${result?.grade || '?'}</strong></span></div>
                <div class="terminal-output">${JSON.stringify(result, null, 2)}</div>
            </div>
        `;
    });
}

function showSslModal() {
    showModal('Test SSL/TLS', `
        <div class="form-group">
            <label>Hostname</label>
            <input class="form-input" id="modal-ssl-host" placeholder="example.com">
        </div>
        <div class="form-group">
            <label>Port</label>
            <input class="form-input" id="modal-ssl-port" type="number" value="443">
        </div>
    `, async () => {
        const hostname = document.getElementById('modal-ssl-host').value;
        const port = parseInt(document.getElementById('modal-ssl-port').value) || 443;
        if (!hostname) return alert('Hostname required');
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        const result = await API.post('/web/ssl', { hostname, port });
        area.innerHTML = `
            <button class="btn btn-secondary mb-16" onclick="renderWebSecurity(document.getElementById('content-area'))">Back</button>
            <div class="card">
                <div class="card-header"><h3>SSL/TLS Test: ${escapeHtml(hostname)}:${port}</h3></div>
                <div class="terminal-output">${JSON.stringify(result, null, 2)}</div>
            </div>
        `;
    });
}

// ─── Cloud Security ───
async function renderCloudSecurity(area) {
    showLoading(area);
    const data = await API.get('/cloud/audits');
    const audits = data?.audits || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Cloud Security Audits (${audits.length})</h3>
            <button class="btn btn-primary" onclick="showCloudAuditModal()">+ Run Audit</button>
        </div>

        <div class="card">
            <table class="data-table">
                <thead><tr><th>ID</th><th>Provider</th><th>Type</th><th>Created</th></tr></thead>
                <tbody>
                    ${audits.map(a => `
                        <tr>
                            <td class="mono">${escapeHtml(a.id || '')}</td>
                            <td>${escapeHtml(a.provider || '')}</td>
                            <td>${escapeHtml(a.audit_type || '')}</td>
                            <td class="text-dim">${timeAgo(a.created_at)}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="4" class="text-dim">No audits yet. Run a cloud security audit.</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function showCloudAuditModal() {
    showModal('Run Cloud Audit', `
        <div class="form-group">
            <label>Provider</label>
            <select class="form-select" id="modal-cloud-provider">
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
            </select>
        </div>
        <div class="form-group">
            <label>Audit Type</label>
            <select class="form-select" id="modal-cloud-type">
                <option value="full">Full Audit</option>
                <option value="iam">IAM Only</option>
                <option value="network">Network Only</option>
                <option value="storage">Storage Only</option>
            </select>
        </div>
    `, async () => {
        const provider = document.getElementById('modal-cloud-provider').value;
        const auditType = document.getElementById('modal-cloud-type').value;
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        await API.post('/cloud/audit', { provider, audit_type: auditType });
        renderCloudSecurity(area);
    });
}

// ─── Compliance ───
async function renderCompliance(area) {
    showLoading(area);
    const [resultData, fwData] = await Promise.all([
        API.get('/compliance/results'),
        API.get('/compliance/frameworks'),
    ]);

    const results = resultData?.results || [];
    const frameworks = fwData?.frameworks || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Compliance (${results.length} checks)</h3>
            <button class="btn btn-primary" onclick="showComplianceModal()">+ Run Check</button>
        </div>

        <div class="stats-grid">
            ${frameworks.map(fw => `
                <div class="stat-card info">
                    <div class="stat-value" style="font-size:16px;">${escapeHtml(fw.name)}</div>
                    <div class="stat-label">${escapeHtml(fw.description)}</div>
                </div>
            `).join('')}
        </div>

        <div class="card">
            <div class="card-header"><h3>Check Results</h3></div>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Framework</th><th>Created</th></tr></thead>
                <tbody>
                    ${results.map(r => `
                        <tr>
                            <td class="mono">${escapeHtml(r.id || '')}</td>
                            <td>${escapeHtml(r.framework || '')}</td>
                            <td class="text-dim">${timeAgo(r.created_at)}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="3" class="text-dim">No compliance checks run yet</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function showComplianceModal() {
    showModal('Run Compliance Check', `
        <div class="form-group">
            <label>Target</label>
            <input class="form-input" id="modal-comp-target" placeholder="192.168.1.1">
        </div>
        <div class="form-group">
            <label>Framework</label>
            <select class="form-select" id="modal-comp-framework">
                <option value="cis">CIS Benchmarks</option>
                <option value="nist">NIST 800-53</option>
                <option value="pci-dss">PCI DSS</option>
                <option value="iso27001">ISO 27001</option>
                <option value="hipaa">HIPAA</option>
                <option value="soc2">SOC 2</option>
            </select>
        </div>
    `, async () => {
        const target = document.getElementById('modal-comp-target').value;
        const framework = document.getElementById('modal-comp-framework').value;
        if (!target) return alert('Target required');
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        await API.post('/compliance/check', { target, framework });
        renderCompliance(area);
    });
}

// ─── Reports ───
async function renderReports(area) {
    showLoading(area);
    const data = await API.get('/reports');
    const reports = data?.reports || [];

    area.innerHTML = `
        <div class="flex-between mb-16">
            <h3>Reports (${reports.length})</h3>
            <button class="btn btn-primary" onclick="showReportModal()">+ Generate Report</button>
        </div>

        <div class="card">
            <table class="data-table">
                <thead><tr><th>ID</th><th>Title</th><th>Format</th><th>Findings</th><th>Generated</th><th>Actions</th></tr></thead>
                <tbody>
                    ${reports.map(r => `
                        <tr>
                            <td class="mono">${escapeHtml(r.id || '')}</td>
                            <td>${escapeHtml(r.title || '')}</td>
                            <td>${escapeHtml(r.format || '')}</td>
                            <td>${r.finding_count || 0}</td>
                            <td class="text-dim">${timeAgo(r.generated_at)}</td>
                            <td><a href="/api/reports/${r.id}/download" class="btn btn-sm btn-secondary">Download</a></td>
                        </tr>
                    `).join('') || '<tr><td colspan="6" class="text-dim">No reports generated yet</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function showReportModal() {
    showModal('Generate Report', `
        <div class="form-group">
            <label>Project ID</label>
            <input class="form-input" id="modal-rpt-project" placeholder="proj-xxxxx">
        </div>
        <div class="form-group">
            <label>Format</label>
            <select class="form-select" id="modal-rpt-format">
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="markdown">Markdown</option>
            </select>
        </div>
    `, async () => {
        const projectId = document.getElementById('modal-rpt-project').value;
        const format = document.getElementById('modal-rpt-format').value;
        if (!projectId) return alert('Project ID required');
        hideModal();
        const area = document.getElementById('content-area');
        showLoading(area);
        await API.post('/reports/generate', { project_id: projectId, format });
        renderReports(area);
    });
}

// ─── AI Chat ───
function renderChat(area) {
    area.innerHTML = `
        <div class="chat-container" style="height:calc(100vh - var(--header-height) - 48px);">
            <div class="chat-messages" id="chat-messages">
                <div class="chat-message system">
                    CyberSecurity AI Agent ready. Ask me anything about security assessments, penetration testing, or vulnerability analysis.
                </div>
                ${state.chatMessages.map(m => `
                    <div class="chat-message ${m.role}">
                        ${m.role === 'assistant' ? formatMarkdown(m.content) : escapeHtml(m.content)}
                    </div>
                `).join('')}
            </div>
            <div class="chat-input-area">
                <input type="text" id="chat-input" placeholder="Ask about security..."
                       onkeydown="if(event.key==='Enter')sendChat()" ${state.chatLoading ? 'disabled' : ''}>
                <button onclick="sendChat()" ${state.chatLoading ? 'disabled' : ''}>
                    ${state.chatLoading ? '<span class="loading-spinner"></span>' : 'Send'}
                </button>
            </div>
        </div>
    `;
    const msgContainer = document.getElementById('chat-messages');
    msgContainer.scrollTop = msgContainer.scrollHeight;
}

async function sendChat() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message || state.chatLoading) return;

    state.chatMessages.push({ role: 'user', content: message });
    input.value = '';
    state.chatLoading = true;
    renderChat(document.getElementById('content-area'));

    try {
        const data = await API.post('/chat', { message, session_id: 'default' });
        if (data && data.response) {
            state.chatMessages.push({ role: 'assistant', content: data.response });
        } else if (data && data.error) {
            state.chatMessages.push({ role: 'assistant', content: `Error: ${data.error}` });
        }
    } catch (e) {
        state.chatMessages.push({ role: 'assistant', content: `Error: ${e.message}` });
    }

    state.chatLoading = false;
    renderChat(document.getElementById('content-area'));
}

function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    // Code blocks
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Headers
    html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>');
    html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
    // Lists
    html = html.replace(/^- (.+)$/gm, '&#8226; $1');
    // Severity tags
    html = html.replace(/\[CRITICAL\]/g, '<span class="severity critical">CRITICAL</span>');
    html = html.replace(/\[HIGH\]/g, '<span class="severity high">HIGH</span>');
    html = html.replace(/\[MEDIUM\]/g, '<span class="severity medium">MEDIUM</span>');
    html = html.replace(/\[LOW\]/g, '<span class="severity low">LOW</span>');
    html = html.replace(/\[INFO\]/g, '<span class="severity info">INFO</span>');
    // Newlines
    html = html.replace(/\n/g, '<br>');
    return html;
}

// ─── Modal ───
function showModal(title, bodyHtml, onSubmit) {
    let overlay = document.getElementById('modal-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'modal-overlay';
        overlay.className = 'modal-overlay';
        overlay.onclick = (e) => { if (e.target === overlay) hideModal(); };
        document.body.appendChild(overlay);
    }

    overlay.innerHTML = `
        <div class="modal">
            <h2>${title}</h2>
            <div>${bodyHtml}</div>
            <div class="form-actions">
                <button class="btn btn-secondary" onclick="hideModal()">Cancel</button>
                ${onSubmit ? '<button class="btn btn-primary" id="modal-submit-btn">Submit</button>' : ''}
            </div>
        </div>
    `;
    overlay.classList.add('active');

    if (onSubmit) {
        document.getElementById('modal-submit-btn').onclick = onSubmit;
    }

    const firstInput = overlay.querySelector('input, select');
    if (firstInput) firstInput.focus();
}

function hideModal() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.classList.remove('active');
}

// ─── Login ───
function renderLogin() {
    document.getElementById('app').innerHTML = `
        <div class="login-container">
            <div class="login-box">
                <div class="logo">&#9763;</div>
                <h2>CyberSecurity Agent</h2>
                <div class="tagline">AI-Powered Penetration Testing</div>
                <div class="error-msg" id="login-error">Invalid credentials</div>
                <div class="form-group">
                    <input class="form-input" id="login-user" placeholder="Username" value="admin">
                </div>
                <div class="form-group">
                    <input class="form-input" id="login-pass" type="password" placeholder="Password"
                           onkeydown="if(event.key==='Enter')doLogin()">
                </div>
                <button class="btn btn-primary" style="width:100%;justify-content:center;" onclick="doLogin()">Login</button>
            </div>
        </div>
    `;
    document.getElementById('login-pass').focus();
}

async function doLogin() {
    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;
    const errEl = document.getElementById('login-error');

    const data = await API.post('/auth/login', { username, password });
    if (data && data.access_token) {
        state.token = data.access_token;
        state.username = data.username;
        localStorage.setItem('hacking_token', data.access_token);
        localStorage.setItem('hacking_user', data.username);
        renderApp();
    } else {
        errEl.classList.add('visible');
    }
}

function doLogout() {
    state.token = null;
    state.username = null;
    localStorage.removeItem('hacking_token');
    localStorage.removeItem('hacking_user');
    renderLogin();
}

// ─── App Shell ───
function renderApp() {
    document.getElementById('app').innerHTML = `
        <div class="app-container">
            <aside class="sidebar">
                <div class="sidebar-header">
                    <span class="logo">&#9763;</span>
                    <div>
                        <h1>CyberSec Agent</h1>
                        <div class="subtitle">Pentest Dashboard</div>
                    </div>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <div class="nav-item active" data-view="dashboard" onclick="navigate('dashboard')">
                        <span class="icon">&#9632;</span> Dashboard
                    </div>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Operations</div>
                    <div class="nav-item" data-view="targets" onclick="navigate('targets')">
                        <span class="icon">&#9678;</span> Targets
                    </div>
                    <div class="nav-item" data-view="recon" onclick="navigate('recon')">
                        <span class="icon">&#9788;</span> Reconnaissance
                    </div>
                    <div class="nav-item" data-view="vulnerabilities" onclick="navigate('vulnerabilities')">
                        <span class="icon">&#9888;</span> Vulnerabilities
                    </div>
                    <div class="nav-item" data-view="exploits" onclick="navigate('exploits')">
                        <span class="icon">&#9889;</span> Exploitation
                    </div>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Security</div>
                    <div class="nav-item" data-view="web_security" onclick="navigate('web_security')">
                        <span class="icon">&#9741;</span> Web Security
                    </div>
                    <div class="nav-item" data-view="cloud_security" onclick="navigate('cloud_security')">
                        <span class="icon">&#9729;</span> Cloud Security
                    </div>
                    <div class="nav-item" data-view="compliance" onclick="navigate('compliance')">
                        <span class="icon">&#9745;</span> Compliance
                    </div>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Output</div>
                    <div class="nav-item" data-view="reports" onclick="navigate('reports')">
                        <span class="icon">&#9776;</span> Reports
                    </div>
                    <div class="nav-item" data-view="chat" onclick="navigate('chat')">
                        <span class="icon">&#9881;</span> AI Chat
                    </div>
                </div>
            </aside>

            <div class="main-content">
                <header class="header">
                    <div class="header-left">
                        <h2>Dashboard</h2>
                    </div>
                    <div class="header-right">
                        <span class="text-dim" style="font-size:12px;">${escapeHtml(state.username || 'admin')}</span>
                        <button class="header-btn" onclick="doLogout()">Logout</button>
                    </div>
                </header>
                <div class="content-area" id="content-area"></div>
            </div>
        </div>
    `;

    navigate('dashboard');
}

// ─── Init ───
document.addEventListener('DOMContentLoaded', () => {
    if (state.token) {
        renderApp();
    } else {
        renderLogin();
    }
});
