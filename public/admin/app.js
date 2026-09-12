// Central Auth for MCP - Control Center Application Logic
// Pure In-Memory Authentication & Unified Management

const state = {
  token: null, // Strictly in-memory to prevent XSS token theft
  user: null,
  clients: [],
  events: [],
  activeTab: 'overview-tab',
  clientFilter: 'all', // 'all' | 'active' | 'revoked'
  clientSearch: '',
  auditSearch: '',
  auditTypeFilter: 'all',
  auditModeFilter: 'all',
  selectedClientId: null,
  activeSnippetTab: 'claude', // 'claude' | 'cursor' | 'curl'
  currentGeneratedCreds: null,
  confirmCallback: null
};

// --- DOM Element References ---
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const loginForm = document.getElementById('login-form');
const loginBtn = document.getElementById('login-btn');
const loginSpinner = document.getElementById('login-spinner');
const loginError = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');
const navUsername = document.getElementById('nav-username');
const navClientsCount = document.getElementById('nav-clients-count');

// Stats Elements
const statTotalClients = document.getElementById('stat-total-clients');
const statActiveClients = document.getElementById('stat-active-clients');
const statRevokedClients = document.getElementById('stat-revoked-clients');
const statTotalEvents = document.getElementById('stat-total-events');
const statOperationalRate = document.getElementById('stat-operational-rate');

// Tab Navigation
const navTabs = document.querySelectorAll('.nav-tab');
const tabPanes = document.querySelectorAll('.tab-pane');

// Clients View Elements
const clientSearchInput = document.getElementById('client-search-input');
const clearClientSearchBtn = document.getElementById('clear-client-search');
const pillFilterBtns = document.querySelectorAll('.pill-btn');
const countAllEl = document.getElementById('count-all');
const countActiveEl = document.getElementById('count-active');
const countRevokedEl = document.getElementById('count-revoked');
const clientsTableBody = document.getElementById('clients-table-body');

// Audit View Elements
const overviewAuditBody = document.getElementById('overview-audit-body');
const auditTableBody = document.getElementById('audit-table-body');
const refreshAuditBtn = document.getElementById('refresh-audit-btn');
const refreshSpinnerIcon = document.getElementById('refresh-spinner-icon');
const auditSearchInput = document.getElementById('audit-search-input');
const clearAuditSearchBtn = document.getElementById('clear-audit-search');
const auditTypeFilter = document.getElementById('audit-type-filter');
const auditModeFilter = document.getElementById('audit-mode-filter');

// Modals
const createModal = document.getElementById('create-modal');
const createMcpForm = document.getElementById('create-mcp-form');
const createSubmitBtn = document.getElementById('create-submit-btn');
const createSpinner = document.getElementById('create-spinner');
const secretModal = document.getElementById('secret-modal');
const confirmModal = document.getElementById('confirm-modal');
const confirmTitle = document.getElementById('confirm-title');
const confirmMessage = document.getElementById('confirm-message');
const confirmWarning = document.getElementById('confirm-warning');
const confirmActionBtn = document.getElementById('confirm-action-btn');

// Detail Drawer Elements
const detailDrawerBackdrop = document.getElementById('detail-drawer-backdrop');
const closeDrawerBtn = document.getElementById('close-drawer-btn');
const detailStatusPill = document.getElementById('detail-status-pill');
const detailName = document.getElementById('detail-name');
const detailIdLabel = document.getElementById('detail-id-label');
const detailAudience = document.getElementById('detail-audience');
const detailClientId = document.getElementById('detail-client-id');
const detailClientType = document.getElementById('detail-client-type');
const detailCreatedAt = document.getElementById('detail-created-at');
const detailRedirectsList = document.getElementById('detail-redirects-list');
const detailGenTokenBtn = document.getElementById('detail-gen-token-btn');
const detailToggleRevokeBtn = document.getElementById('detail-toggle-revoke-btn');
const detailDeleteBtn = document.getElementById('detail-delete-btn');
const detailRevokeLabel = document.getElementById('detail-revoke-label');
const detailRevokeDesc = document.getElementById('detail-revoke-desc');
const detailMiddlewareSnippet = document.getElementById('detail-middleware-snippet');
const detailEventsCount = document.getElementById('detail-events-count');
const detailAuditBody = document.getElementById('detail-audit-body');

// Secret Reveal Elements
const revealEnvSnippet = document.getElementById('reveal-env-snippet');
const revealAudience = document.getElementById('reveal-audience');
const revealClientId = document.getElementById('reveal-client-id');
const revealSecret = document.getElementById('reveal-secret');
const revealStaticToken = document.getElementById('reveal-static-token');
const revealStaticTokenSection = document.getElementById('reveal-static-token-section');
const revealMcpConfig = document.getElementById('reveal-mcp-config');
const snippetTabs = document.querySelectorAll('.snippet-tab');

// Discovery Previews
const metadataPreview = document.getElementById('metadata-preview');
const jwksPreview = document.getElementById('jwks-preview');

// Integration Guide Elements
const guidePythonCode = document.getElementById('guide-python-code');
const guideNodeCode = document.getElementById('guide-node-code');
const aiAssistantPrompt = document.getElementById('ai-assistant-prompt');
const copyAiPromptBtn = document.getElementById('copy-ai-prompt-btn');

// --- Toast Notification Helper ---
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// --- API Fetch Helper ---
async function apiFetch(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  const response = await fetch(endpoint, {
    ...options,
    headers
  });

  if (response.status === 401 && !endpoint.includes('/login')) {
    handleLogout();
    throw new Error('Session expired. Please log in again.');
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || data.error_description || data.error || `HTTP ${response.status}: Request failed`);
  }
  return data;
}

// --- Date & Time Formatter ---
function formatDateTime(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return isoString;
  }
}

function formatRelativeTime(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    const now = new Date();
    const diffSecs = Math.floor((now - d) / 1000);

    if (diffSecs < 10) return 'just now';
    if (diffSecs < 60) return `${diffSecs}s ago`;
    const diffMins = Math.floor(diffSecs / 60);
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return formatDateTime(isoString);
  } catch {
    return isoString;
  }
}

// --- Escape HTML Helper ---
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// --- Confirmation Modal Helper ---
function showConfirm({ title, message, warning, customHtml = null, confirmText = 'Confirm', confirmClass = 'btn-danger', disableConfirm = false, onConfirm }) {
  confirmTitle.innerText = title || 'Confirm Action';
  confirmMessage.innerText = message || 'Are you sure you want to proceed?';
  
  const customContent = document.getElementById('confirm-custom-content');
  if (customContent) {
    if (customHtml) {
      customContent.innerHTML = customHtml;
      customContent.classList.remove('hidden');
    } else {
      customContent.innerHTML = '';
      customContent.classList.add('hidden');
    }
  }

  if (warning) {
    confirmWarning.innerText = warning;
    confirmWarning.classList.remove('hidden');
  } else {
    confirmWarning.classList.add('hidden');
    confirmWarning.innerText = '';
  }

  confirmActionBtn.className = `btn ${confirmClass}`;
  confirmActionBtn.innerText = confirmText;
  confirmActionBtn.disabled = Boolean(disableConfirm);
  state.confirmCallback = onConfirm;
  confirmModal.classList.remove('hidden');
}

function hideConfirm() {
  confirmModal.classList.add('hidden');
  confirmActionBtn.disabled = false;
  state.confirmCallback = null;
  const customContent = document.getElementById('confirm-custom-content');
  if (customContent) {
    customContent.innerHTML = '';
    customContent.classList.add('hidden');
  }
}

confirmActionBtn.addEventListener('click', () => {
  if (typeof state.confirmCallback === 'function') {
    const cb = state.confirmCallback;
    hideConfirm();
    cb();
  } else {
    hideConfirm();
  }
});

document.querySelectorAll('.confirm-cancel-btn').forEach(btn => {
  btn.addEventListener('click', hideConfirm);
});

// --- Tab Switching Logic ---
function switchTab(tabId) {
  state.activeTab = tabId;
  navTabs.forEach(tab => {
    if (tab.getAttribute('data-tab') === tabId) {
      tab.classList.add('active');
    } else {
      tab.classList.remove('active');
    }
  });

  tabPanes.forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });
}

navTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    const targetTab = tab.getAttribute('data-tab');
    switchTab(targetTab);
  });
});

document.querySelectorAll('.view-all-audit-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab('audit-tab'));
});

// --- Authentication Handlers ---
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.classList.add('hidden');
  loginError.innerText = '';

  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    loginError.innerText = 'Please enter both username and password.';
    loginError.classList.remove('hidden');
    return;
  }

  // Loading state
  loginBtn.disabled = true;
  loginSpinner.classList.remove('hidden');

  try {
    const data = await apiFetch('/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    state.token = data.token;
    state.user = data.user;

    navUsername.innerText = state.user?.username || 'admin';
    loginView.classList.add('hidden');
    dashboardView.classList.remove('hidden');

    passwordInput.value = '';
    showToast(`Signed in as ${state.user?.username || 'admin'}`);

    await loadDashboardData();
  } catch (err) {
    loginError.innerText = err.message || 'Authentication failed. Please verify credentials.';
    loginError.classList.remove('hidden');
  } finally {
    loginBtn.disabled = false;
    loginSpinner.classList.add('hidden');
  }
});

function handleLogout() {
  state.token = null;
  state.user = null;
  state.clients = [];
  state.events = [];
  state.selectedClientId = null;

  dashboardView.classList.add('hidden');
  loginView.classList.remove('hidden');
  closeDetailDrawer();
  hideConfirm();
  closeModal(createModal);
  closeModal(secretModal);

  document.getElementById('password').value = '';
  showToast('Signed out of Control Center', 'info');
}

logoutBtn.addEventListener('click', handleLogout);

// --- Load Dashboard Data ---
async function loadDashboardData() {
  await Promise.allSettled([
    loadStats(),
    loadClients(),
    loadAuditEvents(),
    loadDiscoveryPreviews()
  ]);
  updateGuideSnippets();
}

function updateOperationalRate(total, active) {
  if (statOperationalRate) {
    if (total > 0) {
      const rate = ((active / total) * 100).toFixed(1);
      statOperationalRate.innerText = `${rate}% operational rate`;
    } else {
      statOperationalRate.innerText = '100% operational rate';
    }
  }
}

// 1. Stats
async function loadStats() {
  try {
    const data = await apiFetch('/admin/api/stats');
    if (data.stats) {
      const total = data.stats.totalClients ?? 0;
      const active = data.stats.activeClients ?? 0;
      statTotalClients.innerText = total;
      statActiveClients.innerText = active;
      statRevokedClients.innerText = data.stats.revokedClients ?? 0;
      statTotalEvents.innerText = data.stats.totalEvents ?? 0;
      updateOperationalRate(total, active);
    }
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// 2. Clients
async function loadClients() {
  try {
    clientsTableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted"><span class="spinner inline-spinner mr-2"></span> Loading MCP servers...</td></tr>`;
    const data = await apiFetch('/admin/api/clients');
    state.clients = data.clients || [];

    updateClientCounts();
    renderClientsTable();
  } catch (err) {
    clientsTableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Failed to load MCP servers: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function updateClientCounts() {
  const total = state.clients.length;
  const active = state.clients.filter(c => !c.revoked).length;
  const revoked = state.clients.filter(c => c.revoked).length;

  if (navClientsCount) navClientsCount.innerText = total;
  if (countAllEl) countAllEl.innerText = total;
  if (countActiveEl) countActiveEl.innerText = active;
  if (countRevokedEl) countRevokedEl.innerText = revoked;

  statTotalClients.innerText = total;
  statActiveClients.innerText = active;
  statRevokedClients.innerText = revoked;
  updateOperationalRate(total, active);
  updateGuideSnippets();
}

function renderClientsTable() {
  let filtered = state.clients;

  // Status filter
  if (state.clientFilter === 'active') {
    filtered = filtered.filter(c => !c.revoked);
  } else if (state.clientFilter === 'revoked') {
    filtered = filtered.filter(c => c.revoked);
  }

  // Search filter
  if (state.clientSearch) {
    const q = state.clientSearch.toLowerCase();
    filtered = filtered.filter(c => 
      (c.name && c.name.toLowerCase().includes(q)) ||
      (c.audience && c.audience.toLowerCase().includes(q)) ||
      (c.client_id && c.client_id.toLowerCase().includes(q))
    );
  }

  if (filtered.length === 0) {
    const isFiltered = state.clientSearch || state.clientFilter !== 'all';
    clientsTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state-cell">
          <div class="empty-state">
            <div class="empty-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            </div>
            <h4>${isFiltered ? 'No matching MCP servers found' : 'No MCP servers registered yet'}</h4>
            <p>${isFiltered ? 'Try adjusting your search terms or status filter.' : 'Register your first MCP server to generate OAuth 2.1 credentials and Mode 2 static tokens.'}</p>
            ${!isFiltered ? `<button class="btn btn-primary btn-sm open-create-modal-btn mt-2">Register First MCP</button>` : ''}
          </div>
        </td>
      </tr>
    `;
    return;
  }

  clientsTableBody.innerHTML = filtered.map(client => {
    const isRevoked = Boolean(client.revoked);
    return `
      <tr class="${isRevoked ? 'row-revoked' : ''}">
        <td>
          <div class="client-name-cell">
            <strong class="client-display-name">${escapeHtml(client.name || 'Unnamed MCP')}</strong>
            <span class="client-type-label text-muted">${escapeHtml(client.client_type || 'confidential')}</span>
          </div>
        </td>
        <td>
          <span class="aud-tag font-mono">${escapeHtml(client.audience || '—')}</span>
        </td>
        <td>
          <div class="code-copy-cell">
            <code class="font-mono text-muted text-xs">${escapeHtml(client.client_id || '—')}</code>
            <button class="btn-icon copy-text-btn" data-copy="${escapeHtml(client.client_id)}" title="Copy Client ID">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </td>
        <td>
          ${isRevoked 
            ? '<span class="status-badge revoked"><span class="badge-dot red"></span>Revoked</span>' 
            : '<span class="status-badge active"><span class="badge-dot green"></span>Active</span>'}
        </td>
        <td class="text-muted text-xs whitespace-nowrap">
          ${formatDateTime(client.created_at)}
        </td>
        <td class="text-right">
          <div class="row-actions">
            <button class="btn btn-xs btn-ghost action-detail-btn" data-id="${escapeHtml(client.client_id)}" title="Inspect details, config, and audit events">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              <span>Details</span>
            </button>
            <button class="btn btn-xs btn-secondary action-token-btn" data-id="${escapeHtml(client.client_id)}" title="Generate a fresh 1-year or permanent Mode 2 static token">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
              <span>Token</span>
            </button>
            ${isRevoked
              ? `<button class="btn btn-xs btn-success-outline action-unrevoke-btn" data-id="${escapeHtml(client.client_id)}" title="Restore client access">Unrevoke</button>`
              : `<button class="btn btn-xs btn-danger-outline action-revoke-btn" data-id="${escapeHtml(client.client_id)}" title="Revoke all access immediately">Revoke</button>`
            }
            <button class="btn btn-xs btn-danger-subtle action-delete-btn" data-id="${escapeHtml(client.client_id)}" title="Permanently delete client record">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
              <span>Delete</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// Filter pills listener
pillFilterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    pillFilterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.clientFilter = btn.getAttribute('data-filter');
    renderClientsTable();
  });
});

// Client search listener
clientSearchInput.addEventListener('input', (e) => {
  state.clientSearch = e.target.value.trim();
  if (state.clientSearch) {
    clearClientSearchBtn.classList.remove('hidden');
  } else {
    clearClientSearchBtn.classList.add('hidden');
  }
  renderClientsTable();
});

clearClientSearchBtn.addEventListener('click', () => {
  clientSearchInput.value = '';
  state.clientSearch = '';
  clearClientSearchBtn.classList.add('hidden');
  renderClientsTable();
  clientSearchInput.focus();
});

// Delegated action handlers on client table
clientsTableBody.addEventListener('click', (e) => {
  const detailBtn = e.target.closest('.action-detail-btn');
  if (detailBtn) {
    const clientId = detailBtn.getAttribute('data-id');
    openClientDrawer(clientId);
    return;
  }

  const tokenBtn = e.target.closest('.action-token-btn');
  if (tokenBtn) {
    const clientId = tokenBtn.getAttribute('data-id');
    confirmGenerateStaticToken(clientId);
    return;
  }

  const revokeBtn = e.target.closest('.action-revoke-btn');
  if (revokeBtn) {
    const clientId = revokeBtn.getAttribute('data-id');
    confirmRevokeClient(clientId);
    return;
  }

  const unrevokeBtn = e.target.closest('.action-unrevoke-btn');
  if (unrevokeBtn) {
    const clientId = unrevokeBtn.getAttribute('data-id');
    confirmUnrevokeClient(clientId);
    return;
  }

  const deleteBtn = e.target.closest('.action-delete-btn');
  if (deleteBtn) {
    const clientId = deleteBtn.getAttribute('data-id');
    confirmDeleteClient(clientId);
    return;
  }

  const copyBtn = e.target.closest('.copy-text-btn');
  if (copyBtn) {
    const text = copyBtn.getAttribute('data-copy');
    copyToClipboard(text);
  }
});

// 3. Audit Log
async function loadAuditEvents() {
  try {
    if (refreshSpinnerIcon) refreshSpinnerIcon.classList.add('spin-animation');
    const data = await apiFetch('/admin/api/audit?limit=100');
    state.events = data.events || [];

    renderOverviewAudit();
    renderFullAudit();
    
    // If drawer is currently open, also refresh drawer mini table
    if (state.selectedClientId) {
      renderDrawerAudit(state.selectedClientId);
    }
  } catch (err) {
    console.error('Failed to load audit events:', err);
  } finally {
    if (refreshSpinnerIcon) {
      setTimeout(() => refreshSpinnerIcon.classList.remove('spin-animation'), 400);
    }
  }
}

refreshAuditBtn.addEventListener('click', async () => {
  await loadAuditEvents();
  showToast('Audit log updated');
});

function getEventBadge(eventType) {
  const t = (eventType || '').toLowerCase();
  if (t.includes('issued') || t.includes('created') || t.includes('success')) {
    return `<span class="badge badge-success">${escapeHtml(eventType)}</span>`;
  }
  if (t.includes('rotated')) {
    return `<span class="badge badge-purple">${escapeHtml(eventType)}</span>`;
  }
  if (t.includes('deleted')) {
    return `<span class="badge badge-danger">${escapeHtml(eventType)}</span>`;
  }
  if (t.includes('failed') || t.includes('rejected') || t.includes('invalid')) {
    return `<span class="badge badge-danger">${escapeHtml(eventType)}</span>`;
  }
  if (t.includes('revoked')) {
    return `<span class="badge badge-warning">${escapeHtml(eventType)}</span>`;
  }
  if (t.includes('registered')) {
    return `<span class="badge badge-primary">${escapeHtml(eventType)}</span>`;
  }
  return `<span class="badge badge-neutral">${escapeHtml(eventType)}</span>`;
}

function getModeBadge(mode) {
  if (!mode) return '<span class="text-muted text-xs">—</span>';
  const m = mode.toLowerCase();
  if (m === 'oauth2_code') {
    return `<span class="font-mono text-xs text-blue">oauth2_code</span>`;
  }
  if (m === 'static_token') {
    return `<span class="font-mono text-xs text-purple">static_token</span>`;
  }
  if (m === 'client_credentials') {
    return `<span class="font-mono text-xs text-green">client_creds</span>`;
  }
  return `<span class="font-mono text-xs text-muted">${escapeHtml(mode)}</span>`;
}

function renderOverviewAudit() {
  const recent = state.events.slice(0, 6);
  if (recent.length === 0) {
    overviewAuditBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No token events recorded yet.</td></tr>`;
    return;
  }

  overviewAuditBody.innerHTML = recent.map(evt => `
    <tr>
      <td class="text-muted text-xs whitespace-nowrap">${formatRelativeTime(evt.timestamp)}</td>
      <td>${getEventBadge(evt.event_type)}</td>
      <td><code class="font-mono text-xs text-muted">${escapeHtml(evt.client_id || '—')}</code></td>
      <td><span class="aud-tag font-mono">${escapeHtml(evt.audience || '—')}</span></td>
      <td>${getModeBadge(evt.auth_mode)}</td>
      <td class="text-muted text-xs font-mono max-w-sm truncate" title="${escapeHtml(JSON.stringify(evt.details || {}))}">
        ${escapeHtml(formatEventDetails(evt.details))}
      </td>
    </tr>
  `).join('');
}

function renderFullAudit() {
  let filtered = state.events;

  // Event type filter
  if (state.auditTypeFilter !== 'all') {
    filtered = filtered.filter(e => {
      const et = (e.event_type || '').toLowerCase();
      return et.includes(state.auditTypeFilter.toLowerCase());
    });
  }

  // Auth mode filter
  if (state.auditModeFilter !== 'all') {
    filtered = filtered.filter(e => {
      const m = (e.auth_mode || '').toLowerCase();
      return m === state.auditModeFilter.toLowerCase();
    });
  }

  // Search filter
  if (state.auditSearch) {
    const q = state.auditSearch.toLowerCase();
    filtered = filtered.filter(e => 
      (e.client_id && e.client_id.toLowerCase().includes(q)) ||
      (e.audience && e.audience.toLowerCase().includes(q)) ||
      (e.ip_address && e.ip_address.toLowerCase().includes(q)) ||
      (e.details && JSON.stringify(e.details).toLowerCase().includes(q))
    );
  }

  if (filtered.length === 0) {
    auditTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center py-5 text-muted">
          No audit events match current search or filters.
        </td>
      </tr>
    `;
    return;
  }

  auditTableBody.innerHTML = filtered.map(evt => `
    <tr>
      <td class="text-muted text-xs whitespace-nowrap" title="${formatDateTime(evt.timestamp)}">
        ${formatRelativeTime(evt.timestamp)}
      </td>
      <td>${getEventBadge(evt.event_type)}</td>
      <td>
        <code class="font-mono text-xs ${evt.client_id ? 'text-primary' : 'text-muted'}">
          ${escapeHtml(evt.client_id || '—')}
        </code>
      </td>
      <td><span class="aud-tag font-mono">${escapeHtml(evt.audience || '—')}</span></td>
      <td>${getModeBadge(evt.auth_mode)}</td>
      <td><span class="font-mono text-xs text-muted">${escapeHtml(evt.ip_address || '—')}</span></td>
      <td class="text-muted text-xs max-w-md">
        <div class="event-details-content font-mono" title="${escapeHtml(JSON.stringify(evt.details || {}, null, 2))}">
          ${escapeHtml(formatEventDetails(evt.details))}
        </div>
      </td>
    </tr>
  `).join('');
}

function formatEventDetails(details) {
  if (!details) return '—';
  if (typeof details === 'string') return details;
  const parts = [];
  if (details.grant_type) parts.push(`grant:${details.grant_type}`);
  if (details.username) parts.push(`user:${details.username}`);
  if (details.reason) parts.push(`reason:${details.reason}`);
  if (details.client_name) parts.push(`name:${details.client_name}`);
  if (details.error) parts.push(`err:${details.error}`);
  if (parts.length > 0) return parts.join(', ');
  try {
    const raw = JSON.stringify(details);
    return raw === '{}' ? '—' : raw;
  } catch {
    return '—';
  }
}

// Audit filter listeners
auditSearchInput.addEventListener('input', (e) => {
  state.auditSearch = e.target.value.trim();
  if (state.auditSearch) {
    clearAuditSearchBtn.classList.remove('hidden');
  } else {
    clearAuditSearchBtn.classList.add('hidden');
  }
  renderFullAudit();
});

clearAuditSearchBtn.addEventListener('click', () => {
  auditSearchInput.value = '';
  state.auditSearch = '';
  clearAuditSearchBtn.classList.add('hidden');
  renderFullAudit();
  auditSearchInput.focus();
});

auditTypeFilter.addEventListener('change', (e) => {
  state.auditTypeFilter = e.target.value;
  renderFullAudit();
});

auditModeFilter.addEventListener('change', (e) => {
  state.auditModeFilter = e.target.value;
  renderFullAudit();
});

// 4. Discovery & Keys Preview
async function loadDiscoveryPreviews() {
  try {
    const metaRes = await fetch('/.well-known/oauth-authorization-server');
    if (metaRes.ok) {
      const meta = await metaRes.json();
      metadataPreview.textContent = JSON.stringify(meta, null, 2);
      if (meta.issuer) state.issuerUrl = meta.issuer;
      if (meta.jwks_uri) state.jwksUri = meta.jwks_uri;
      updateGuideSnippets();
    } else {
      metadataPreview.textContent = '// Failed to load OAuth metadata';
    }
  } catch (err) {
    metadataPreview.textContent = `// Error loading metadata: ${err.message}`;
  }

  try {
    const jwksRes = await fetch('/.well-known/jwks.json');
    if (jwksRes.ok) {
      const jwks = await jwksRes.json();
      jwksPreview.textContent = JSON.stringify(jwks, null, 2);
    } else {
      jwksPreview.textContent = '// Failed to load JWKS';
    }
  } catch (err) {
    jwksPreview.textContent = `// Error loading JWKS: ${err.message}`;
  }
}

// --- Integration Guide Logic ---
function updateGuideSnippets() {
  const origin = window.location.origin;
  const issuer = state.issuerUrl || origin;
  const jwksUri = state.jwksUri || `${origin}/.well-known/jwks.json`;
  const discoveryUri = `${issuer}/.well-known/oauth-authorization-server`;
  const audience = '<your-mcp-audience>';

  if (guidePythonCode) {
    guidePythonCode.textContent = 
`# 1. Install required verification dependencies:
# pip install PyJWT[crypto] requests

from fastapi import FastAPI
from sdk.python.mcp_auth_middleware import McpAuthMiddleware

app = FastAPI(title="My Protected MCP Server")

# 2. Add drop-in Central Auth verification middleware
app.add_middleware(
    McpAuthMiddleware,
    jwks_uri="${jwksUri}",
    audience="${audience}"
)

@app.get("/mcp/tools")
async def list_tools():
    # Only valid signed tokens for "${audience}" reach here
    return {"tools": [...]}`;
  }

  if (guideNodeCode) {
    guideNodeCode.textContent = 
`// 1. Zero external npm dependencies (uses native Node.js crypto/https)
const express = require('express');
const { createMcpAuthMiddleware } = require('./sdk/node/mcp-auth-middleware.js');

const app = express();

// 2. Add drop-in Central Auth verification middleware
app.use(createMcpAuthMiddleware({
  jwksUri: '${jwksUri}',
  audience: '${audience}'
}));

app.get('/mcp/tools', (req, res) => {
  // Only valid signed tokens for "${audience}" reach here
  res.json({ tools: [...] });
});

app.listen(8080);`;
  }

  if (aiAssistantPrompt) {
    aiAssistantPrompt.textContent = 
`I need to add authentication to my MCP server so it works with our Central Auth MCP system. Do NOT write custom authentication logic or generate new auth files — use the existing official middleware for this exact purpose.

Details for this integration:
- JWKS URI: ${jwksUri}
- Audience: ${audience}
- Discovery endpoint: ${discoveryUri}

If my MCP server is written in Python:
1. Install the middleware from the repository (sdk/python/mcp_auth_middleware.py)
   Required dependencies: pip install PyJWT[crypto] requests
2. Add it as FastAPI / Starlette middleware:
   from sdk.python.mcp_auth_middleware import McpAuthMiddleware
   app.add_middleware(McpAuthMiddleware, jwks_uri="${jwksUri}", audience="${audience}")
3. Do not implement JWT verification manually — the middleware handles signature verification against the JWKS URI, audience checking, clock skew, and token expiry.

If my MCP server is written in Node.js/TypeScript:
1. Use the equivalent Node middleware (sdk/node/mcp-auth-middleware.js)
   Zero external npm dependencies (uses native Node.js standard modules crypto/https).
2. Wire it in as Express/Connect/Fastify middleware before your MCP route handlers:
   const { createMcpAuthMiddleware } = require('./sdk/node/mcp-auth-middleware.js');
   app.use(createMcpAuthMiddleware({ jwksUri: '${jwksUri}', audience: '${audience}' }));

The goal: any request without a valid signed token for this exact audience must be rejected with 401. Valid tokens are issued by our Central Auth server, not by this MCP server itself — do not add login, registration, or token-issuing logic here, only verification.`;
  }
}

if (copyAiPromptBtn) {
  copyAiPromptBtn.addEventListener('click', () => {
    if (aiAssistantPrompt) {
      copyToClipboard(aiAssistantPrompt.textContent, copyAiPromptBtn);
    }
  });
}

document.querySelectorAll('.guide-lang-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.guide-lang-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const lang = btn.getAttribute('data-lang');
    document.querySelectorAll('.guide-code-pane').forEach(pane => {
      pane.classList.remove('active');
    });
    const targetPane = document.getElementById(`guide-code-${lang}`);
    if (targetPane) targetPane.classList.add('active');
  });
});

// --- Client Detail Slide-Over Drawer ---
function openClientDrawer(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  if (!client) {
    showToast('Client not found', 'danger');
    return;
  }

  state.selectedClientId = clientId;

  // Metadata
  detailName.innerText = client.name || 'Unnamed MCP';
  detailIdLabel.innerText = `ID: ${client.client_id}`;
  detailAudience.innerText = client.audience || '—';
  detailClientId.innerText = client.client_id;
  detailClientType.innerText = client.client_type || 'confidential';
  detailCreatedAt.innerText = formatDateTime(client.created_at);

  // Status Pill
  if (client.revoked) {
    detailStatusPill.className = 'drawer-status-pill revoked';
    detailStatusPill.innerText = 'Revoked';
  } else {
    detailStatusPill.className = 'drawer-status-pill active';
    detailStatusPill.innerText = 'Active';
  }

  // Redirect URIs chips
  const redirects = Array.isArray(client.redirect_uris) ? client.redirect_uris : [];
  if (redirects.length > 0) {
    detailRedirectsList.innerHTML = redirects.map(uri => 
      `<span class="tag font-mono">${escapeHtml(uri)}</span>`
    ).join('');
  } else {
    detailRedirectsList.innerHTML = `<span class="text-muted text-xs">No redirect URIs specified.</span>`;
  }

  // Revoke/Unrevoke toggle styling
  if (client.revoked) {
    detailRevokeLabel.innerText = 'Restore Client Access';
    detailRevokeDesc.innerText = 'Re-authorizes token validation for this MCP server.';
    detailToggleRevokeBtn.className = 'btn btn-sm btn-success';
    detailToggleRevokeBtn.innerText = 'Unrevoke Client';
  } else {
    detailRevokeLabel.innerText = 'Revoke Client Access';
    detailRevokeDesc.innerText = 'Immediately invalidates both Mode 1 and Mode 2 tokens.';
    detailToggleRevokeBtn.className = 'btn btn-sm btn-danger';
    detailToggleRevokeBtn.innerText = 'Revoke Client';
  }

  // Middleware Snippet
  const origin = window.location.origin;
  detailMiddlewareSnippet.textContent = 
`// Node.js Express Drop-In Middleware Example
import { createAuthMiddleware } from './middleware/auth.js';

app.use(createAuthMiddleware({
  authServerUrl: '${origin}',
  expectedAudience: '${client.audience}'
}));`;

  // Render client-specific audit history
  renderDrawerAudit(clientId);

  // Show Drawer
  detailDrawerBackdrop.classList.remove('hidden');
}

function closeDetailDrawer() {
  detailDrawerBackdrop.classList.add('hidden');
  state.selectedClientId = null;
}

closeDrawerBtn.addEventListener('click', closeDetailDrawer);

detailDrawerBackdrop.addEventListener('click', (e) => {
  if (e.target === detailDrawerBackdrop) {
    closeDetailDrawer();
  }
});

function renderDrawerAudit(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  const clientAud = client?.audience;

  const filtered = state.events.filter(e => 
    e.client_id === clientId || 
    (clientAud && e.audience === clientAud)
  );

  detailEventsCount.innerText = `${filtered.length} event${filtered.length === 1 ? '' : 's'}`;

  if (filtered.length === 0) {
    detailAuditBody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-muted">No audit events recorded for this MCP server.</td></tr>`;
    return;
  }

  detailAuditBody.innerHTML = filtered.slice(0, 15).map(evt => `
    <tr>
      <td class="text-muted text-xs whitespace-nowrap">${formatRelativeTime(evt.timestamp)}</td>
      <td>${getEventBadge(evt.event_type)}</td>
      <td>${getModeBadge(evt.auth_mode)}</td>
      <td class="text-muted text-xs font-mono">${escapeHtml(formatEventDetails(evt.details))}</td>
    </tr>
  `).join('');
}

// Drawer Actions
detailGenTokenBtn.addEventListener('click', () => {
  if (state.selectedClientId) {
    confirmGenerateStaticToken(state.selectedClientId);
  }
});

detailToggleRevokeBtn.addEventListener('click', () => {
  if (!state.selectedClientId) return;
  const client = state.clients.find(c => c.client_id === state.selectedClientId);
  if (!client) return;

  if (client.revoked) {
    confirmUnrevokeClient(state.selectedClientId);
  } else {
    confirmRevokeClient(state.selectedClientId);
  }
});

if (detailDeleteBtn) {
  detailDeleteBtn.addEventListener('click', () => {
    if (state.selectedClientId) {
      confirmDeleteClient(state.selectedClientId);
    }
  });
}

// --- Modal Helpers ---
function openModal(modalEl) {
  modalEl.classList.remove('hidden');
}

function closeModal(modalEl) {
  modalEl.classList.add('hidden');
}

document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) {
      closeModal(backdrop);
    }
  });
});

document.querySelectorAll('.modal-close-btn, .modal-cancel-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const modal = e.target.closest('.modal-backdrop');
    if (modal) closeModal(modal);
  });
});

// Open Register Modal
document.querySelectorAll('.open-create-modal-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    createMcpForm.reset();
    const adv = document.getElementById('create-advanced-options');
    if (adv) adv.open = false;
    openModal(createModal);
    document.getElementById('new-mcp-name').focus();
  });
});

// --- Register MCP Server Submission ---
createMcpForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const name = document.getElementById('new-mcp-name').value.trim();
  const audienceEl = document.getElementById('new-mcp-audience');
  const audience = audienceEl ? audienceEl.value.trim() : '';
  const redirectsEl = document.getElementById('new-mcp-redirects');
  const redirectsRaw = redirectsEl ? redirectsEl.value.trim() : '';

  const redirect_uris = redirectsRaw
    ? redirectsRaw.split(',').map(s => s.trim()).filter(Boolean)
    : undefined;

  const payload = { name };
  if (audience) payload.audience = audience;
  if (redirect_uris && redirect_uris.length > 0) payload.redirect_uris = redirect_uris;
  const lifetimeEl = document.getElementById('new-mcp-token-lifetime');
  if (lifetimeEl) {
    payload.staticTokenDays = parseInt(lifetimeEl.value, 10);
  }

  createSubmitBtn.disabled = true;
  createSpinner.classList.remove('hidden');

  try {
    const res = await apiFetch('/admin/api/clients', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    closeModal(createModal);
    showToast(`MCP server "${name}" protected successfully!`);

    // Display One-Time Secret Reveal Modal
    state.currentGeneratedCreds = res;
    displaySecretRevealModal(res);

    // Refresh client list, stats, and audit log
    await loadClients();
    await loadStats();
    await loadAuditEvents();
  } catch (err) {
    showToast(err.message || 'Failed to register MCP server', 'danger');
  } finally {
    createSubmitBtn.disabled = false;
    createSpinner.classList.add('hidden');
  }
});

// --- One-Time Secret Reveal Modal Logic ---
function displaySecretRevealModal(data) {
  const client = data.client || {};
  const secret = data.clientSecret || '';
  const staticTokenObj = data.staticToken;
  const staticToken = staticTokenObj?.token || '';
  const envSnippet = data.envSnippet || '';

  if (revealEnvSnippet) {
    revealEnvSnippet.textContent = envSnippet;
  }

  // Ensure advanced details starts closed
  const secretAdv = document.getElementById('secret-advanced-details');
  if (secretAdv) secretAdv.open = false;

  revealAudience.innerText = client.audience || '—';
  revealClientId.value = client.client_id || '—';
  revealSecret.value = secret;

  const staticLabel = document.getElementById('reveal-static-token-label');
  if (staticLabel) {
    if (staticTokenObj?.expiresIn && staticTokenObj.expiresIn > 365 * 86400) {
      staticLabel.innerText = 'Mode 2 Static Token (No Expiry / 10-Year RS256 JWT)';
    } else {
      staticLabel.innerText = 'Mode 2 Static Token (1-Year Signed RS256 JWT)';
    }
  }

  if (staticToken) {
    revealStaticTokenSection.classList.remove('hidden');
    revealStaticToken.value = staticToken;
  } else {
    revealStaticTokenSection.classList.add('hidden');
    revealStaticToken.value = '';
  }

  // Update Config Snippet for current snippet tab
  updateConfigSnippet();

  openModal(secretModal);
}

// Config Snippet Tab Switching
snippetTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    snippetTabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    state.activeSnippetTab = tab.getAttribute('data-snippet');
    updateConfigSnippet();
  });
});

function updateConfigSnippet() {
  if (!state.currentGeneratedCreds) return;
  const { client, staticToken } = state.currentGeneratedCreds;
  const origin = window.location.origin;
  const serverName = (client?.name || 'my-mcp-server').toLowerCase().replace(/\s+/g, '-');
  const token = staticToken?.token || 'YOUR_STATIC_JWT_TOKEN';
  const aud = client?.audience || 'mcp-service';

  let code = '';
  if (state.activeSnippetTab === 'claude') {
    code = JSON.stringify({
      mcpServers: {
        [serverName]: {
          command: "node",
          args: ["/absolute/path/to/server.js"],
          env: {
            CENTRAL_AUTH_URL: origin,
            MCP_AUDIENCE: aud,
            MCP_STATIC_TOKEN: token
          }
        }
      }
    }, null, 2);
  } else if (state.activeSnippetTab === 'cursor') {
    code = JSON.stringify({
      mcp: {
        servers: {
          [serverName]: {
            url: `http://localhost:8000/sse`,
            headers: {
              Authorization: `Bearer ${token}`
            }
          }
        }
      }
    }, null, 2);
  } else if (state.activeSnippetTab === 'curl') {
    code = `# Test MCP Server Request with Static Fallback Token
curl -X POST http://localhost:8000/mcp \\
  -H "Authorization: Bearer ${token}" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'`;
  }

  revealMcpConfig.textContent = code;
}

// --- Action Confirmations ---

// 1. Generate Static Token
function confirmGenerateStaticToken(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  const clientName = escapeHtml(client?.name || clientId);

  const customHtml = `
    <div style="margin-top: 8px;">
      <label for="confirm-token-lifetime" style="font-size: 12px; font-weight: 600; display: block; margin-bottom: 4px; color: var(--text-primary);">
        Static Token Lifetime:
      </label>
      <select id="confirm-token-lifetime" class="form-select" style="width: 100%; margin-bottom: 8px;">
        <option value="365" selected>1 Year (365 Days) — Default (Recommended)</option>
        <option value="0">No Expiry (10 Years) — Permanent Production</option>
        <option value="90">90 Days — Temporary / Testing</option>
      </select>
    </div>
  `;

  showConfirm({
    title: 'Generate Fresh Static Token',
    message: `Generate a fresh Mode 2 static token for "${clientName}"?`,
    customHtml: customHtml,
    warning: 'Generating a new token automatically invalidates the previous static token for this client — the client itself remains active.',
    confirmText: 'Generate Token',
    confirmClass: 'btn-primary',
    onConfirm: async () => {
      const lifetimeEl = document.getElementById('confirm-token-lifetime');
      const days = lifetimeEl ? parseInt(lifetimeEl.value, 10) : 365;
      try {
        const res = await apiFetch(`/admin/api/clients/${encodeURIComponent(clientId)}/static-token`, {
          method: 'POST',
          body: JSON.stringify({ days: days })
        });
        const isNoExpiry = days === 0;
        showToast(isNoExpiry ? 'Generated permanent (10-year) static token' : `Generated fresh ${days === 365 ? '1-year' : `${days}-day`} static token`);

        // Reveal the newly generated token in the reveal modal
        state.currentGeneratedCreds = {
          client: client,
          clientSecret: '(Unchanged existing client secret)',
          staticToken: res.staticToken
        };
        displaySecretRevealModal(state.currentGeneratedCreds);

        await loadStats();
        await loadAuditEvents();
      } catch (err) {
        showToast(err.message || 'Failed to generate static token', 'danger');
      }
    }
  });

  // Dynamic warning if No Expiry is chosen
  setTimeout(() => {
    const selectEl = document.getElementById('confirm-token-lifetime');
    const warningEl = document.getElementById('confirm-warning');
    if (selectEl && warningEl) {
      selectEl.addEventListener('change', () => {
        if (selectEl.value === '0') {
          warningEl.innerText = 'SECURITY WARNING: No expiry — only use for long-running production MCPs where automatic rotation isn\'t feasible; revoke manually if compromised.';
          warningEl.classList.remove('hidden');
        } else {
          warningEl.innerText = 'Generating a new token automatically invalidates the previous static token for this client — the client itself remains active.';
        }
      });
    }
  }, 50);
}

// 2. Revoke Client
function confirmRevokeClient(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  showConfirm({
    title: 'Revoke MCP Server Access',
    message: `Are you sure you want to revoke "${client?.name || clientId}"?`,
    warning: 'CRITICAL: All existing tokens (both Mode 1 OAuth 2.1 access tokens and Mode 2 static tokens) for this audience will immediately be rejected by any MCP server.',
    confirmText: 'Revoke Server Access',
    confirmClass: 'btn-danger',
    onConfirm: async () => {
      try {
        await apiFetch(`/admin/api/clients/${encodeURIComponent(clientId)}/revoke`, {
          method: 'POST'
        });
        showToast(`Revoked "${client?.name || clientId}"`);

        // If drawer is open for this client, update drawer view
        if (state.selectedClientId === clientId) {
          openClientDrawer(clientId);
        }

        await loadClients();
        await loadStats();
        await loadAuditEvents();
      } catch (err) {
        showToast(err.message || 'Failed to revoke client', 'danger');
      }
    }
  });
}

// 3. Unrevoke Client
function confirmUnrevokeClient(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  showConfirm({
    title: 'Restore MCP Server Access',
    message: `Re-authorize "${client?.name || clientId}"?`,
    confirmText: 'Restore Access',
    confirmClass: 'btn-success',
    onConfirm: async () => {
      try {
        await apiFetch(`/admin/api/clients/${encodeURIComponent(clientId)}/unrevoke`, {
          method: 'POST'
        });
        showToast(`Restored access for "${client?.name || clientId}"`);

        // If drawer is open for this client, update drawer view
        if (state.selectedClientId === clientId) {
          openClientDrawer(clientId);
        }

        await loadClients();
        await loadStats();
        await loadAuditEvents();
      } catch (err) {
        showToast(err.message || 'Failed to restore client', 'danger');
      }
    }
  });
}

// 4. Permanently Delete Client (Destructive with Typed-Name Confirmation)
function confirmDeleteClient(clientId) {
  const client = state.clients.find(c => c.client_id === clientId);
  if (!client) return;
  const clientName = client.name || clientId;

  const customHtml = `
    <div style="margin-top: 10px;">
      <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">
        To confirm permanent deletion, type <strong style="color: var(--text-primary); user-select: all;">${escapeHtml(clientName)}</strong> below:
      </p>
      <input type="text" id="confirm-delete-input" autocomplete="off" placeholder="Type MCP name to confirm" style="width: 100%; padding: 8px 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background: var(--surface-container-low); color: var(--text-primary); font-size: 13px; font-family: var(--font-sans);">
    </div>
  `;

  showConfirm({
    title: 'Permanently Delete MCP Server',
    message: `Are you sure you want to permanently delete "${escapeHtml(clientName)}"?`,
    warning: 'PERMANENT DELETION: This action CANNOT be undone (unlike Revoke, which can be unrevoked). All client credentials will be destroyed immediately. Historical token audit events are preserved for compliance.',
    customHtml: customHtml,
    confirmText: 'Delete MCP Server',
    confirmClass: 'btn-danger',
    disableConfirm: true,
    onConfirm: async () => {
      try {
        await apiFetch(`/admin/api/clients/${encodeURIComponent(clientId)}`, {
          method: 'DELETE'
        });
        showToast(`Permanently deleted "${clientName}"`);

        // If drawer is open for this client, close it
        if (state.selectedClientId === clientId) {
          closeDetailDrawer();
        }

        await loadClients();
        await loadStats();
        await loadAuditEvents();
      } catch (err) {
        showToast(err.message || 'Failed to delete MCP server', 'danger');
      }
    }
  });

  setTimeout(() => {
    const inputEl = document.getElementById('confirm-delete-input');
    if (inputEl) {
      inputEl.focus();
      inputEl.addEventListener('input', () => {
        confirmActionBtn.disabled = inputEl.value.trim() !== clientName;
      });
    }
  }, 50);
}

// --- Universal Copy to Clipboard Handler ---
document.addEventListener('click', (e) => {
  const copyBtn = e.target.closest('.copy-btn');
  if (!copyBtn) return;
  if (copyBtn.id === 'copy-ai-prompt-btn') return;

  const targetId = copyBtn.getAttribute('data-target');
  if (!targetId) return;

  const targetEl = document.getElementById(targetId);
  if (!targetEl) return;

  let textToCopy = '';
  if (targetEl.tagName === 'INPUT' || targetEl.tagName === 'TEXTAREA') {
    textToCopy = targetEl.value;
  } else {
    textToCopy = targetEl.innerText || targetEl.textContent;
  }

  copyToClipboard(textToCopy, copyBtn);
});

async function copyToClipboard(text, btnElement = null) {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      // Fallback for older contexts
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }

    showToast('Copied to clipboard!');

    if (btnElement) {
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add('btn-copied');
      btnElement.innerHTML = `
        <span class="material-symbols-outlined" style="font-size: 16px;">check</span>
        <span>Copied!</span>
      `;
      setTimeout(() => {
        btnElement.classList.remove('btn-copied');
        btnElement.innerHTML = originalHtml;
      }, 2000);
    }
  } catch (err) {
    showToast('Could not copy to clipboard', 'danger');
  }
}

// Initial state check
// Since tokens are strictly kept in memory, ensure login view is shown on fresh load.
window.addEventListener('DOMContentLoaded', () => {
  loginView.classList.remove('hidden');
  dashboardView.classList.add('hidden');
  document.getElementById('username').focus();
});
