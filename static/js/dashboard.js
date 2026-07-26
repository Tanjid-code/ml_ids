// ==================== GLOBALS ====================
let socket;
let threatTypeChart, alertTrendChart;
let audioCtx = null;
let currentPage = 'dashboard';
let alertsCurrentPage = 1;
let alertsTotalPages = 1;
let dashCurrentPage = 1;
let dashTotalPages = 1;

// ==================== INIT ====================
document.addEventListener('DOMContentLoaded', function () {
    initSocket();
    initCharts();
    setupCommonListeners();
    loadAll();
    startAutoRefresh();
});

// ==================== SOCKET ====================
function initSocket() {
    try {
        socket = io();
        socket.on('connect', () =>
            showToast('Connected to IDS server', 'success')
        );
        socket.on('disconnect', () =>
            showToast('Disconnected from server', 'error')
        );

        socket.on('new_alert', (alert) => {
            if (currentPage === 'dashboard' || currentPage === 'alerts') {
                loadAlerts();
                loadStats();
            }
            showToast(
                `🚨 ${alert.severity.toUpperCase()}: ${fmt(alert.type)}`,
                'warning'
            );
            playSound(alert.severity);
        });

        socket.on('ml_alert', (data) => {
            showToast(
                `🤖 ML Attack: ${data.attack_probability}% from ${data.source_ip}`,
                'warning'
            );
        });

        socket.on('notification', () => updateNotifCount());
        socket.on('stats_update', (s) => updateNetStats(s));
    } catch (e) {
        console.error('Socket init error:', e);
    }
}

// ==================== CHARTS ====================
function initCharts() {
    const isDark = !document.body.classList.contains('light-theme');
    const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
    const tickColor = isDark ? '#a0aec0' : '#4a5568';

    const tCtx = document.getElementById('threatTypeChart');
    if (tCtx) {
        threatTypeChart = new Chart(tCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#ef4444', '#f59e0b', '#10b981',
                        '#3b82f6', '#8b5cf6', '#ec4899',
                        '#06b6d4', '#84cc16'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: tickColor, font: { size: 11 } }
                    }
                }
            }
        });
    }

    const aCtx = document.getElementById('alertTrendChart');
    if (aCtx) {
        alertTrendChart = new Chart(aCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Alerts by Severity',
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#dc2626', '#ef4444', '#f59e0b', '#10b981'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: gridColor },
                        ticks: { color: tickColor }
                    },
                    x: {
                        grid: { color: gridColor },
                        ticks: { color: tickColor }
                    }
                }
            }
        });
    }
}

// ==================== LOAD ALL ====================
async function loadAll() {
    await Promise.all([
        loadAlerts(),
        loadStats(),
        loadNetStats(),
        checkStatus(),
        updateNotifCount()
    ]);
}

// ==================== LOAD ALERTS ====================
async function loadAlerts() {
    try {
        let url;
        let page;

        if (currentPage === 'alerts') {
            // Alerts page — use filters
            const severity = document.getElementById('severityFilter')?.value || '';
            const status   = document.getElementById('statusFilter')?.value || '';
            const type     = document.getElementById('typeFilter')?.value || '';
            const ip       = document.getElementById('ipSearch')?.value.trim() || '';
            page = alertsCurrentPage;

            url = `/api/alerts?limit=50&page=${page}`;
            if (severity) url += `&severity=${severity}`;
            if (status)   url += `&status=${status}`;
            if (type)     url += `&type=${type}`;
            if (ip)       url += `&source_ip=${ip}`;
        } else {
            // Dashboard — recent only
            const sev = document.getElementById('dashSeverityFilter')?.value || '';
            page = dashCurrentPage;
            url = `/api/alerts?limit=20&page=${page}`;
            if (sev) url += `&severity=${sev}`;
        }

        const resp = await fetch(url);
        if (!resp.ok) return;
        const data = await resp.json();

        const alerts = data.alerts || data;
        const total  = data.total || alerts.length;
        const tp     = data.total_pages || 1;
        const cp     = data.page || 1;

        if (currentPage === 'alerts') {
            alertsTotalPages  = tp;
            alertsCurrentPage = cp;
            renderAlertsTable(alerts, true);
            updateAlertsPagination();
        } else {
            dashTotalPages  = tp;
            dashCurrentPage = cp;
            renderAlertsTable(alerts, false);
            updateDashPagination();
        }

    } catch (e) {
        console.error('loadAlerts error:', e);
    }
}

function renderAlertsTable(alerts, withCheckbox) {
    const tbody = document.getElementById('alertsBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const colspan = withCheckbox ? 9 : 9;

    if (!alerts || !alerts.length) {
        tbody.innerHTML = `
            <tr class="no-data-row">
                <td colspan="${colspan}">
                    <div class="no-data">
                        <span class="no-data-icon">🔍</span>
                        <p>No alerts found</p>
                        <p class="no-data-hint">
                            Start monitoring or adjust filters
                        </p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    alerts.forEach(a => {
        const row = withCheckbox
            ? buildRowWithCheckbox(a)
            : buildRow(a);
        tbody.appendChild(row);
    });
}

// ==================== TABLE ROW BUILDERS ====================
function buildRow(alert) {
    const row      = document.createElement('tr');
    row.dataset.alertId = alert.id;
    row.className  = 'alert-row';

    const time     = new Date(alert.timestamp).toLocaleString();
    const typeName = fmt(alert.type);
    const ruleId   = alert.rule_id || '';
    const ruleName = alert.rule_name || '';
    const src      = alert.detection_source || 'rule';
    const srcClass = `source-${src}`;

    row.innerHTML = `
        <td class="cell-time">${time}</td>
        <td><strong>${typeName}</strong></td>
        <td>
            <span class="ip-link"
                  data-ip="${escHtml(alert.source_ip)}"
                  onclick="showIPDetails('${escHtml(alert.source_ip)}')">
                ${escHtml(alert.source_ip)}
            </span>
        </td>
        <td>${escHtml(alert.destination_ip || 'N/A')}:${alert.destination_port || 'N/A'}</td>
        <td>
            <span class="rule-badge" title="${escHtml(ruleName)}">
                ${escHtml(ruleId) || 'N/A'}
            </span>
        </td>
        <td>
            <span class="severity-badge severity-${alert.severity}">
                ${alert.severity.toUpperCase()}
            </span>
        </td>
        <td>
            <span class="source-badge ${srcClass}">
                ${src.toUpperCase()}
            </span>
        </td>
        <td>
            <span class="status-badge status-${alert.status}">
                ${fmtStatus(alert.status)}
            </span>
        </td>
        <td>
            <div class="action-buttons">
                <button class="action-btn explain"
                        onclick="explainAlert(${alert.id})" title="Explain">🤖</button>
                <button class="action-btn details"
                        onclick="showAlertDetails(${alert.id})" title="Details">📋</button>
                <button class="action-btn acknowledge"
                        onclick="acknowledgeAlert(${alert.id})" title="Acknowledge">✓</button>
                <button class="action-btn block-ip"
                        onclick="blockIP('${escHtml(alert.source_ip)}')" title="Block">🚫</button>
                <button class="action-btn false-pos"
                        onclick="markFalsePos(${alert.id})" title="False Positive">⚠️</button>
            </div>
        </td>
    `;
    return row;
}

function buildRowWithCheckbox(alert) {
    const row      = document.createElement('tr');
    row.dataset.alertId = alert.id;

    const time     = new Date(alert.timestamp).toLocaleString();
    const typeName = fmt(alert.type);
    const src      = alert.detection_source || 'rule';
    const srcClass = `source-${src}`;

    row.innerHTML = `
        <td>
            <input type="checkbox" class="alert-checkbox"
                   value="${alert.id}" onchange="updateSelectedCount()">
        </td>
        <td class="cell-time">${time}</td>
        <td><strong>${typeName}</strong></td>
        <td>
            <span class="ip-link"
                  data-ip="${escHtml(alert.source_ip)}"
                  onclick="showIPDetails('${escHtml(alert.source_ip)}')">
                ${escHtml(alert.source_ip)}
            </span>
        </td>
        <td>${escHtml(alert.destination_ip || 'N/A')}:${alert.destination_port || 'N/A'}</td>
        <td>
            <span class="severity-badge severity-${alert.severity}">
                ${alert.severity.toUpperCase()}
            </span>
        </td>
        <td>
            <span class="source-badge ${srcClass}">
                ${src.toUpperCase()}
            </span>
        </td>
        <td>
            <span class="status-badge status-${alert.status}">
                ${fmtStatus(alert.status)}
            </span>
        </td>
        <td>
            <div class="action-buttons">
                <button class="action-btn explain"
                        onclick="explainAlert(${alert.id})" title="Explain">🤖</button>
                <button class="action-btn details"
                        onclick="showAlertDetails(${alert.id})" title="Details">📋</button>
                <button class="action-btn acknowledge"
                        onclick="acknowledgeAlert(${alert.id})" title="Acknowledge">✓</button>
                <button class="action-btn block-ip"
                        onclick="blockIP('${escHtml(alert.source_ip)}')" title="Block">🚫</button>
                <button class="action-btn false-pos"
                        onclick="markFalsePos(${alert.id})" title="False Positive">⚠️</button>
            </div>
        </td>
    `;
    return row;
}

// ==================== PAGINATION ====================
function updateAlertsPagination() {
    const pag = document.getElementById('alertsPagination');
    if (!pag) return;
    pag.style.display = alertsTotalPages > 1 ? 'flex' : 'none';
    setEl('pageInfo', `Page ${alertsCurrentPage} of ${alertsTotalPages}`);
}

function updateDashPagination() {
    const pag = document.getElementById('dashPagination');
    if (!pag) return;
    pag.style.display = dashTotalPages > 1 ? 'flex' : 'none';
    setEl('dashPageInfo', `Page ${dashCurrentPage} of ${dashTotalPages}`);
}

// ==================== STATS & CHARTS ====================
async function loadStats() {
    try {
        const resp  = await fetch('/api/alerts/stats');
        if (!resp.ok) return;
        const stats = await resp.json();

        setEl('totalAlerts',    stats.total || 0);
        setEl('criticalAlerts', stats.by_severity?.critical || 0);
        setEl('highAlerts',     stats.by_severity?.high || 0);
        setEl('mediumAlerts',   stats.by_severity?.medium || 0);
        setEl('lowAlerts',      stats.by_severity?.low || 0);

        updateCharts(stats);
    } catch (e) {
        console.error('loadStats error:', e);
    }
}

function updateCharts(stats) {
    if (threatTypeChart && stats.by_type) {
        const types = Object.keys(stats.by_type);
        const vals  = Object.values(stats.by_type);
        threatTypeChart.data.labels           = types.map(fmt);
        threatTypeChart.data.datasets[0].data = vals;
        threatTypeChart.update();
    }

    if (alertTrendChart && stats.by_severity) {
        const s = stats.by_severity;
        alertTrendChart.data.datasets[0].data = [
            s.critical || 0, s.high || 0,
            s.medium || 0, s.low || 0
        ];
        alertTrendChart.update();
    }
}

async function loadNetStats() {
    try {
        const resp  = await fetch('/api/network/stats');
        if (!resp.ok) return;
        const stats = await resp.json();
        updateNetStats(stats);

        const cResp = await fetch('/api/network/connections');
        if (cResp.ok) {
            const conns = await cResp.json();
            setEl('activeConnections', conns.length || 0);
        }
    } catch (e) {
        console.error('loadNetStats error:', e);
    }
}

function updateNetStats(stats) {
    setEl('bytesRecv',   fmtBytes(stats.bytes_recv || 0));
    setEl('bytesSent',   fmtBytes(stats.bytes_sent || 0));
    setEl('packetsRecv', (stats.packets_recv || 0).toLocaleString());
    setEl('packetsSent', (stats.packets_sent || 0).toLocaleString());
}

async function checkStatus() {
    try {
        const resp = await fetch('/api/monitor/status');
        if (!resp.ok) return;
        const data = await resp.json();
        setStatus(data.is_running);
    } catch (e) {
        console.error('checkStatus error:', e);
    }
}

function setStatus(running) {
    const ind  = document.getElementById('statusIndicator');
    const text = ind?.querySelector('.status-text');
    if (running) {
        ind?.classList.add('running');
        if (text) text.textContent = 'Monitoring';
    } else {
        ind?.classList.remove('running');
        if (text) text.textContent = 'Stopped';
    }
}

// ==================== NOTIFICATIONS ====================
async function loadNotifs() {
    try {
        const resp   = await fetch('/api/notifications');
        if (!resp.ok) return;
        const notifs = await resp.json();
        const list   = document.getElementById('notificationList');
        if (!list) return;

        if (!notifs.length) {
            list.innerHTML = '<p class="empty-notifications">No notifications</p>';
            return;
        }

        list.innerHTML = notifs.map(n => `
            <div class="notification-item ${n.read ? '' : 'unread'}"
                 onclick="markNotifRead(${n.id})">
                <div class="notification-title">${escHtml(n.title)}</div>
                <div class="notification-message">${escHtml(n.message)}</div>
                <div class="notification-time">${timeAgo(n.timestamp)}</div>
            </div>
        `).join('');
    } catch (e) {
        console.error('loadNotifs error:', e);
    }
}

async function markNotifRead(id) {
    try {
        await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
        updateNotifCount();
        loadNotifs();
    } catch (e) {
        console.error('markNotifRead error:', e);
    }
}

async function updateNotifCount() {
    try {
        const r  = await fetch('/api/notifications/count');
        if (!r.ok) return;
        const d  = await r.json();
        const el = document.getElementById('notifCount');
        if (el) {
            el.textContent   = d.count || 0;
            el.style.display = d.count > 0 ? 'block' : 'none';
        }
    } catch (e) { /* silent */ }
}

// ==================== COMMON LISTENERS ====================
function setupCommonListeners() {
    // Monitor start/stop
    on('startBtn', 'click', async () => {
        try {
            const r = await fetch('/api/monitor/start', { method: 'POST' });
            const d = await r.json();
            showToast(d.message, 'success');
            setStatus(true);
        } catch (e) { showToast('Failed to start', 'error'); }
    });

    on('stopBtn', 'click', async () => {
        try {
            const r = await fetch('/api/monitor/stop', { method: 'POST' });
            const d = await r.json();
            showToast(d.message, 'info');
            setStatus(false);
        } catch (e) { showToast('Failed to stop', 'error'); }
    });

    // Clear alerts
    on('clearBtn', 'click', async () => {
        if (!confirm('Clear all alerts? Cannot be undone.')) return;
        try {
            await fetch('/api/alerts/clear', { method: 'POST' });
            loadAlerts();
            loadStats();
            showToast('Alerts cleared', 'success');
        } catch (e) { showToast('Failed', 'error'); }
    });

    // Refresh
    on('refreshBtn', 'click', () => {
        loadAll();
        showToast('Refreshed', 'info');
    });

    // Dashboard severity filter
    on('dashSeverityFilter', 'change', () => {
        dashCurrentPage = 1;
        loadAlerts();
    });

    // Dashboard pagination
    on('dashPrevPage', 'click', () => {
        if (dashCurrentPage > 1) { dashCurrentPage--; loadAlerts(); }
    });
    on('dashNextPage', 'click', () => {
        if (dashCurrentPage < dashTotalPages) { dashCurrentPage++; loadAlerts(); }
    });

    // Theme toggle
    on('themeBtn', 'click', () => {
        document.body.classList.toggle('light-theme');
        const isLight = document.body.classList.contains('light-theme');
        const btn     = document.getElementById('themeBtn');
        if (btn) btn.textContent = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
    });

    // Restore theme
    if (localStorage.getItem('theme') === 'light') {
        document.body.classList.add('light-theme');
        const btn = document.getElementById('themeBtn');
        if (btn) btn.textContent = '🌙 Dark Mode';
    }

    // Notification bell
    const bell = document.getElementById('notificationBell');
    if (bell) {
        bell.addEventListener('click', (e) => {
            e.stopPropagation();
            const panel = document.getElementById('notificationPanel');
            panel?.classList.toggle('active');
            if (panel?.classList.contains('active')) loadNotifs();
        });
    }

    on('markAllRead', 'click', async () => {
        try {
            await fetch('/api/notifications/read-all', { method: 'POST' });
            updateNotifCount();
            loadNotifs();
            showToast('All read', 'success');
        } catch (e) { showToast('Failed', 'error'); }
    });

    // Close modals
    ['closeModal', 'closeExplainModal', 'closeIpModal'].forEach(id => {
        on(id, 'click', () => closeAllModals());
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAllModals();
    });

    document.querySelectorAll('.modal').forEach(m => {
        m.addEventListener('click', (e) => {
            if (e.target === m) closeAllModals();
        });
    });

    // Close notification panel on outside click
    document.addEventListener('click', (e) => {
        const panel = document.getElementById('notificationPanel');
        const bell  = document.getElementById('notificationBell');
        if (panel && bell &&
            !panel.contains(e.target) &&
            !bell.contains(e.target)) {
            panel.classList.remove('active');
        }
    });

    // Alerts page listeners
    setupAlertsPageListeners();
}

// ==================== ALERTS PAGE LISTENERS ====================
function setupAlertsPageListeners() {
    on('applyFilters', 'click', () => {
        alertsCurrentPage = 1;
        loadAlerts();
    });

    on('clearFilters', 'click', () => {
        ['severityFilter', 'statusFilter', 'typeFilter', 'ipSearch'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        alertsCurrentPage = 1;
        loadAlerts();
        showToast('Filters cleared', 'info');
    });

    on('selectAll', 'change', function () {
        document.querySelectorAll('.alert-checkbox').forEach(cb => cb.checked = this.checked);
        updateSelectedCount();
    });

    on('headerCheckbox', 'change', function () {
        document.querySelectorAll('.alert-checkbox').forEach(cb => cb.checked = this.checked);
        updateSelectedCount();
    });

    on('prevPage', 'click', () => {
        if (alertsCurrentPage > 1) { alertsCurrentPage--; loadAlerts(); }
    });
    on('nextPage', 'click', () => {
        if (alertsCurrentPage < alertsTotalPages) { alertsCurrentPage++; loadAlerts(); }
    });

    on('bulkAcknowledge', 'click', bulkAcknowledge);
    on('bulkFalsePositive', 'click', bulkFalsePositive);
    on('bulkDelete', 'click', bulkDelete);
}

// ==================== BULK ACTIONS ====================
function updateSelectedCount() {
    const selected = document.querySelectorAll('.alert-checkbox:checked').length;
    const countEl  = document.getElementById('selectedCount');
    if (countEl) countEl.textContent = `(${selected} selected)`;

    ['bulkAcknowledge', 'bulkFalsePositive', 'bulkDelete'].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = selected === 0;
    });
}

async function bulkAcknowledge() {
    const ids = getSelectedIds();
    if (!ids.length) return;
    try {
        await Promise.all(ids.map(id =>
            fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' })
        ));
        showToast(`${ids.length} acknowledged`, 'success');
        loadAlerts(); loadStats();
    } catch (e) { showToast('Failed', 'error'); }
}

async function bulkFalsePositive() {
    const ids = getSelectedIds();
    if (!ids.length) return;
    const reason = prompt(`Mark ${ids.length} as false positive?\nReason:`);
    if (reason === null) return;
    try {
        await Promise.all(ids.map(id =>
            fetch(`/api/alerts/${id}/false-positive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: reason || '' }),
            })
        ));
        showToast(`${ids.length} marked false positive`, 'success');
        loadAlerts(); loadStats();
    } catch (e) { showToast('Failed', 'error'); }
}

async function bulkDelete() {
    const ids = getSelectedIds();
    if (!ids.length) return;
    if (!confirm(`Delete ${ids.length} alert(s)?`)) return;
    try {
        await Promise.all(ids.map(id =>
            fetch(`/api/alerts/${id}`, { method: 'DELETE' })
        ));
        showToast(`${ids.length} deleted`, 'success');
        loadAlerts(); loadStats();
    } catch (e) { showToast('Failed', 'error'); }
}

function getSelectedIds() {
    return Array.from(
        document.querySelectorAll('.alert-checkbox:checked')
    ).map(cb => cb.value);
}

// ==================== MODAL ACTIONS ====================

// AI Explanation
async function explainAlert(alertId) {
    try {
        showToast('Loading explanation...', 'info');
        const r = await fetch(`/api/explain/${alertId}`);
        if (!r.ok) { showToast('Not found', 'error'); return; }
        const ex = await r.json();

        const riskCls = `risk-${(ex.risk_level || 'unknown')}`;
        const rd      = ex.rule_details || {};
        const td      = ex.technical_details || {};

        const body = document.getElementById('explainModalBody');
        if (!body) return;

        body.innerHTML = `
            <div class="explanation-section">
                <h3>📋 Summary</h3>
                <p>${escHtml(ex.summary || '')}</p>
                <span class="risk-badge ${riskCls}">Risk: ${ex.risk_level || 'UNKNOWN'}</span>
                ${td.ml_detected ? `<span class="source-badge source-ml" style="margin-left:10px">ML Detected (${td.ml_confidence || 0}%)</span>` : ''}
                ${td.detection_source ? `<span class="source-badge source-${td.detection_source}" style="margin-left:10px">${td.detection_source.toUpperCase()}</span>` : ''}
            </div>

            <div class="rule-detail-box">
                <h3>🎯 Why This Was Flagged</h3>
                <div class="rule-field"><label>Rule ID</label><div class="value">${escHtml(rd.rule_id || 'N/A')}</div></div>
                <div class="rule-field"><label>Rule Name</label><div class="value">${escHtml(rd.rule_name || 'N/A')}</div></div>
                <div class="rule-field"><label>Detection Method</label><div class="value">${escHtml(rd.detection_method || 'N/A')}</div></div>
                <div class="rule-field"><label>Pattern</label><div class="pattern">${escHtml(rd.rule_pattern || 'N/A')}</div></div>
                <div class="rule-field"><label>Explanation</label><div class="explanation-text">${escHtml(rd.why_this_is_attack || 'N/A')}</div></div>
                ${rd.payload_sample && rd.payload_sample !== 'N/A' ? `<div class="rule-field"><label>Payload Sample</label><div class="pattern">${escHtml(rd.payload_sample)}</div></div>` : ''}
            </div>

            <div class="explanation-section"><h3>❓ What Is This?</h3><p>${escHtml(ex.what_is_it || '')}</p></div>
            <div class="explanation-section"><h3>⚙️ How It Works</h3><p style="white-space:pre-line">${escHtml(ex.how_it_works || '')}</p></div>
            <div class="explanation-section"><h3>⚠️ Why Dangerous</h3><p>${escHtml(ex.why_dangerous || '')}</p></div>
            <div class="explanation-section"><h3>📰 Real Example</h3><p>${escHtml(ex.real_example || '')}</p></div>
            <div class="explanation-section"><h3>💥 Impact</h3><ul>${(ex.potential_impact || []).map(i => `<li>${escHtml(i)}</li>`).join('')}</ul></div>
            <div class="explanation-section"><h3>✅ You CAN Do</h3><ul class="can-do-list">${(ex.user_can_do || []).map(i => `<li>✓ ${escHtml(i)}</li>`).join('')}</ul></div>
            <div class="explanation-section"><h3>❌ You CANNOT Do</h3><ul class="cannot-do-list">${(ex.user_cannot_do || []).map(i => `<li>✗ ${escHtml(i)}</li>`).join('')}</ul></div>
            <div class="explanation-section"><h3>🛡️ Prevention</h3><ul>${(ex.prevention_tips || []).map(i => `<li>💡 ${escHtml(i)}</li>`).join('')}</ul></div>

            <div class="tech-details">
                <h3>🔧 Technical Details</h3>
                <p><strong>Source IP:</strong> ${escHtml(td.source_ip || 'N/A')}</p>
                <p><strong>Destination:</strong> ${escHtml(td.destination_ip || 'N/A')}:${td.destination_port || 'N/A'}</p>
                <p><strong>Severity:</strong> ${escHtml(td.severity || 'N/A')}</p>
                <p><strong>Detection:</strong> ${escHtml(td.detection_source || 'rule')}</p>
                <p><strong>Time:</strong> ${td.timestamp ? new Date(td.timestamp).toLocaleString() : 'N/A'}</p>
            </div>

            <div style="margin-top:15px;display:flex;gap:8px;flex-wrap:wrap">
                <button class="btn btn-success" onclick="acknowledgeAlert(${alertId});closeAllModals()">✓ Acknowledge</button>
                <button class="btn btn-danger" onclick="blockIP('${escHtml(td.source_ip || '')}');closeAllModals()">🚫 Block IP</button>
                <button class="btn btn-warning" onclick="markFalsePos(${alertId});closeAllModals()">⚠️ False Positive</button>
            </div>
        `;

        openModal('explainModal');
    } catch (e) {
        console.error('explainAlert error:', e);
        showToast('Failed to load explanation', 'error');
    }
}

// Alert details
async function showAlertDetails(alertId) {
    try {
        const r     = await fetch(`/api/alerts/${alertId}`);
        if (!r.ok) { showToast('Not found', 'error'); return; }
        const alert = await r.json();
        const body  = document.getElementById('alertModalBody');
        if (!body) return;

        const src = alert.detection_source || 'rule';
        const srcBadge = `<span class="source-badge source-${src}">${src.toUpperCase()}</span>`;

        body.innerHTML = `
            <div class="alert-detail-grid">
                <div class="detail-item"><label>ID</label><span>${alert.id}</span></div>
                <div class="detail-item"><label>Type</label><span>${fmt(alert.type)}</span></div>
                <div class="detail-item"><label>Severity</label><span class="severity-badge severity-${alert.severity}">${alert.severity?.toUpperCase()}</span></div>
                <div class="detail-item"><label>Detection</label>${srcBadge}${alert.ml_detected ? `<span style="margin-left:5px;font-size:12px">ML: ${alert.ml_confidence || 0}%</span>` : ''}</div>
                <div class="detail-item"><label>Source IP</label><span class="ip-link" onclick="showIPDetails('${escHtml(alert.source_ip)}')">${escHtml(alert.source_ip)}</span></div>
                <div class="detail-item"><label>Destination</label><span>${escHtml(alert.destination_ip || 'N/A')}:${alert.destination_port || 'N/A'}</span></div>
                <div class="detail-item"><label>Status</label><span class="status-badge status-${alert.status}">${fmtStatus(alert.status)}</span></div>
                <div class="detail-item"><label>Time</label><span>${new Date(alert.timestamp).toLocaleString()}</span></div>
                <div class="detail-item"><label>Rule ID</label><span class="rule-badge">${escHtml(alert.rule_id || 'N/A')}</span></div>
                <div class="detail-item"><label>Rule Name</label><span>${escHtml(alert.rule_name || 'N/A')}</span></div>
                <div class="detail-item full-width"><label>Pattern</label><span style="font-family:monospace;font-size:12px;word-break:break-all">${escHtml(alert.rule_regex || 'N/A')}</span></div>
                <div class="detail-item full-width"><label>Explanation</label><span>${escHtml(alert.rule_explanation || 'N/A')}</span></div>
                <div class="detail-item full-width"><label>Description</label><span>${escHtml(alert.description || 'N/A')}</span></div>
                ${alert.notes ? `<div class="detail-item full-width"><label>Notes</label><pre>${escHtml(alert.notes)}</pre></div>` : ''}
            </div>
            <div style="margin-top:15px;display:flex;gap:8px;flex-wrap:wrap">
                <button class="btn btn-info" onclick="explainAlert(${alert.id});closeAllModals()">🤖 Explain</button>
                <button class="btn btn-success" onclick="acknowledgeAlert(${alert.id})">✓ Acknowledge</button>
                <button class="btn btn-danger" onclick="blockIP('${escHtml(alert.source_ip)}')">🚫 Block</button>
                <button class="btn btn-warning" onclick="markFalsePos(${alert.id})">⚠️ False Positive</button>
                <button class="btn btn-secondary" onclick="addNotePrompt(${alert.id})">📝 Add Note</button>
            </div>
        `;

        openModal('alertModal');
    } catch (e) {
        console.error('showAlertDetails error:', e);
        showToast('Failed', 'error');
    }
}

// IP Details
async function showIPDetails(ip) {
    if (!ip || ip === 'N/A') return;
    try {
        const r    = await fetch(`/api/ip/details/${ip}`);
        if (!r.ok) { showToast('IP not found', 'error'); return; }
        const data = await r.json();
        const body = document.getElementById('ipModalBody');
        if (!body) return;

        const blockedBadge = data.is_blocked
            ? '<span class="severity-badge severity-critical">BLOCKED</span>'
            : '<span class="severity-badge severity-low">Not Blocked</span>';
        const wlBadge = data.is_whitelisted
            ? '<span class="severity-badge severity-low">WHITELISTED</span>' : '';

        const traffic = data.traffic || {};
        const sources = data.detection_sources || {};

        const attackHtml = Object.entries(data.attack_types || {})
            .map(([k, v]) => `<li>${fmt(k)}: <strong>${v}</strong></li>`)
            .join('') || '<li>None</li>';

        const sevHtml = Object.entries(data.severity_breakdown || {})
            .map(([k, v]) => `<li><span class="severity-badge severity-${k}">${k.toUpperCase()}</span>: ${v}</li>`)
            .join('') || '<li>None</li>';

        const srcHtml = Object.entries(sources)
            .map(([k, v]) => `<span class="source-badge source-${k}">${k}: ${v}</span>`)
            .join(' ') || 'N/A';

        const statusHtml = Object.entries(traffic.status_codes || {})
            .map(([c, n]) => `<span class="rule-badge">${c}: ${n}</span>`)
            .join(' ') || 'N/A';

        body.innerHTML = `
            <div class="ip-detail-grid">
                <div class="ip-detail-item"><label>IP Address</label><div class="val">${escHtml(ip)}</div></div>
                <div class="ip-detail-item"><label>Risk Score</label><div class="val">${data.risk_score || 'N/A'}</div></div>
                <div class="ip-detail-item"><label>Classification</label><div class="val"><span class="classification-badge class-${traffic.classification || 'normal'}">${traffic.classification || 'normal'}</span></div></div>
                <div class="ip-detail-item"><label>Status</label><div class="val">${blockedBadge} ${wlBadge}</div></div>
                <div class="ip-detail-item"><label>First Seen</label><div class="val">${data.first_seen ? new Date(data.first_seen).toLocaleString() : 'N/A'}</div></div>
                <div class="ip-detail-item"><label>Last Seen</label><div class="val">${data.last_seen ? new Date(data.last_seen).toLocaleString() : 'N/A'}</div></div>
                <div class="ip-detail-item"><label>Total Alerts</label><div class="val" style="color:var(--danger)">${data.total_alerts || 0}</div></div>
                <div class="ip-detail-item"><label>Detection Sources</label><div class="val">${srcHtml}</div></div>
            </div>

            ${traffic.total_requests ? `
            <div class="rule-detail-box" style="margin-top:15px">
                <h3>📦 Traffic Stats</h3>
                <div class="ip-detail-grid">
                    <div class="ip-detail-item"><label>Total Requests</label><div class="val">${(traffic.total_requests || 0).toLocaleString()}</div></div>
                    <div class="ip-detail-item"><label>Requests/Min</label><div class="val" style="color:${(traffic.requests_per_min || 0) > 50 ? 'var(--danger)' : 'var(--success)'}">${traffic.requests_per_min || 0}</div></div>
                    <div class="ip-detail-item"><label>Packets In</label><div class="val">${(traffic.packets_in || 0).toLocaleString()}</div></div>
                    <div class="ip-detail-item"><label>Packets Out</label><div class="val">${(traffic.packets_out || 0).toLocaleString()}</div></div>
                    <div class="ip-detail-item"><label>Data In</label><div class="val">${fmtBytes(traffic.bytes_in || 0)}</div></div>
                    <div class="ip-detail-item"><label>Data Out</label><div class="val">${fmtBytes(traffic.bytes_out || 0)}</div></div>
                    <div class="ip-detail-item"><label>Session</label><div class="val">${traffic.session_duration || 'N/A'}</div></div>
                    <div class="ip-detail-item"><label>Status Codes</label><div class="val">${statusHtml}</div></div>
                </div>
            </div>` : ''}

            ${data.total_alerts > 0 ? `
            <div class="rule-detail-box" style="margin-top:15px;border-left-color:var(--danger)">
                <h3>🚨 Threat Info</h3>
                <div class="ip-detail-grid">
                    <div class="ip-detail-item full-width"><label>Attack Types</label><ul>${attackHtml}</ul></div>
                    <div class="ip-detail-item full-width"><label>Severity Breakdown</label><ul>${sevHtml}</ul></div>
                </div>
            </div>` : ''}

            <div style="margin-top:15px;display:flex;gap:8px;flex-wrap:wrap">
                ${!data.is_blocked
                    ? `<button class="btn btn-danger" onclick="blockIPFromModal('${escHtml(ip)}')">🚫 Block</button>`
                    : `<button class="btn btn-success" onclick="unblockIPFromModal('${escHtml(ip)}')">🔓 Unblock</button>`}
                ${!data.is_whitelisted
                    ? `<button class="btn btn-secondary" onclick="whitelistIPFromModal('${escHtml(ip)}')">✅ Whitelist</button>`
                    : `<button class="btn btn-warning" onclick="removeWhitelistFromModal('${escHtml(ip)}')">❌ Remove WL</button>`}
                <button class="btn btn-danger btn-sm" onclick="deleteAlertsByIpFromModal('${escHtml(ip)}')">🗑️ Delete Alerts</button>
                <button class="btn btn-info" onclick="filterByIP('${escHtml(ip)}')">🔍 Show Alerts</button>
            </div>
        `;

        openModal('ipModal');
    } catch (e) {
        console.error('showIPDetails error:', e);
        showToast('Failed', 'error');
    }
}

// ==================== ALERT ACTIONS ====================
async function acknowledgeAlert(alertId) {
    try {
        const r = await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
        if (r.ok) {
            showToast('Acknowledged', 'success');
            const row   = document.querySelector(`tr[data-alert-id="${alertId}"]`);
            const badge = row?.querySelector('.status-badge');
            if (badge) { badge.className = 'status-badge status-acknowledged'; badge.textContent = 'Acknowledged'; }
            loadStats();
        } else { showToast('Failed', 'error'); }
    } catch (e) { showToast('Failed', 'error'); }
}

async function blockIP(ip) {
    if (!ip || ip === 'N/A') return;
    if (!confirm(`Block IP: ${ip}?`)) return;
    const reason = prompt('Reason:') || 'Blocked from dashboard';
    try {
        const r = await fetch('/api/ip/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason }),
        });
        if (r.ok) showToast(`${ip} blocked`, 'success');
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function markFalsePos(alertId) {
    const reason = prompt('Reason (optional):');
    if (reason === null) return;
    try {
        const r = await fetch(`/api/alerts/${alertId}/false-positive`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason || '' }),
        });
        if (r.ok) { showToast('Marked false positive', 'success'); loadAlerts(); loadStats(); }
        else { showToast('Failed', 'error'); }
    } catch (e) { showToast('Failed', 'error'); }
}

async function addNotePrompt(alertId) {
    const note = prompt('Enter note:');
    if (!note?.trim()) return;
    try {
        const r = await fetch(`/api/alerts/${alertId}/note`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ note: note.trim() }),
        });
        if (r.ok) showToast('Note added', 'success');
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

// ==================== IP MANAGEMENT FROM MODAL ====================
async function blockIPFromModal(ip) {
    const reason = prompt('Reason:') || 'Blocked from IP details';
    try {
        const r = await fetch('/api/ip/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason }),
        });
        if (r.ok) { showToast(`${ip} blocked`, 'success'); showIPDetails(ip); }
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function unblockIPFromModal(ip) {
    try {
        const r = await fetch('/api/ip/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        if (r.ok) { showToast(`${ip} unblocked`, 'success'); showIPDetails(ip); }
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function whitelistIPFromModal(ip) {
    try {
        const r = await fetch('/api/ip/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        if (r.ok) { showToast(`${ip} whitelisted`, 'success'); showIPDetails(ip); }
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function removeWhitelistFromModal(ip) {
    try {
        const r = await fetch('/api/ip/whitelist', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        if (r.ok) { showToast('Removed from whitelist', 'success'); showIPDetails(ip); }
        else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function deleteAlertsByIpFromModal(ip) {
    if (!confirm(`Delete ALL alerts from ${ip}?`)) return;
    try {
        const r = await fetch(`/api/alerts/ip/${ip}`, { method: 'DELETE' });
        if (r.ok) {
            const result = await r.json();
            showToast(`Deleted ${result.deleted} alerts`, 'success');
            showIPDetails(ip);
            loadAlerts(); loadStats();
        } else showToast('Failed', 'error');
    } catch (e) { showToast('Failed', 'error'); }
}

async function filterByIP(ip) {
    closeAllModals();
    if (currentPage === 'alerts') {
        const el = document.getElementById('ipSearch');
        if (el) el.value = ip;
        alertsCurrentPage = 1;
        loadAlerts();
    } else {
        window.location.href = `/alerts?ip=${ip}`;
    }
}

// ==================== AUTO REFRESH ====================
function startAutoRefresh() {
    setInterval(() => {
        if (currentPage === 'dashboard') {
            loadStats();
            loadNetStats();
            checkStatus();
            updateNotifCount();
        }
    }, 5000);

    setInterval(() => {
        if (currentPage === 'dashboard') {
            loadAlerts();
        }
    }, 10000);
}

// ==================== UTILITIES ====================
function openModal(id) {
    document.getElementById(id)?.classList.add('active');
}

function closeAllModals() {
    document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
}

function on(id, event, fn) {
    document.getElementById(id)?.addEventListener(event, fn);
}

function setEl(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function fmt(str) {
    if (!str) return 'Unknown';
    return str.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function fmtStatus(s) {
    return fmt(s || 'unknown');
}

function fmtBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k     = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i     = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function timeAgo(ts) {
    if (!ts) return '';
    const diff = (new Date() - new Date(ts)) / 1000;
    if (diff < 60)    return 'Just now';
    if (diff < 3600)  return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hr ago`;
    return new Date(ts).toLocaleDateString();
}

function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showToast(msg, type = 'info') {
    const c = document.getElementById('toastContainer');
    if (!c) return;
    const t     = document.createElement('div');
    t.className = `toast toast-${type}`;
    const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
    t.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${escHtml(msg)}</span>`;
    c.appendChild(t);
    setTimeout(() => {
        t.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => t.remove(), 300);
    }, 4000);
}

function getAudioCtx() {
    if (!audioCtx) {
        try {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        } catch (e) { return null; }
    }
    if (audioCtx.state === 'suspended') {
        audioCtx.resume().catch(() => {});
    }
    return audioCtx;
}

function playSound(severity) {
    if (severity !== 'critical' && severity !== 'high') return;
    try {
        const ctx = getAudioCtx();
        if (!ctx) return;
        const osc = ctx.createOscillator();
        const g   = ctx.createGain();
        osc.connect(g);
        g.connect(ctx.destination);
        osc.frequency.value = severity === 'critical' ? 880 : 660;
        g.gain.setValueAtTime(0.3, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.5);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.5);
    } catch (e) { /* silent */ }
}