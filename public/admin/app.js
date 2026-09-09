// Central Auth for MCP - Dashboard Application Logic

const state = {
  token: localStorage.getItem('mcp_admin_token') || null,
  user: JSON.parse(localStorage.getItem('mcp_admin_user') || 'null'),
  clients: [],
  events: []
};

// DOM Elements
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');
const navUsername = document.getElementById('nav-username');

// Stats Elements
const statTotalClients = document.getElementById('stat-total-clients');
const statActiveClients = document.getElementById('stat-active-clients');
const statRevokedClients = document.getElementById('stat-revoked-clients');
const statTotalEvents = document.getElementById('stat-total-events');

// Tables
const clientsTableBody = document.getElementById('clients-table-body');
const auditTableBody = document.getElementById('audit-table-body');
const refreshAuditBtn = document.getElementById('refresh-audit-btn');

// Modals
const createModal = document.getElementById('create-modal');
const secretModal = document.getElementById('secret-modal');
const openCreateModalBtn = document.getElementById('open-create-modal-btn');
const createMcpForm = document.getElementById('create-mcp-form');

// Discovery Previews
const metadataPreview = document.getElementById('metadata-preview');
const jwksPreview = document.getElementById('jwks-preview');

// Toast Helper
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 200);
  }, 3000);
}

// API Fetch Helper with Auth Header
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
    throw new Error('Session expired, please log in again.');
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || data.error_description || data.error || 'Request failed');
  }
  return data;
}

// Authentication Handlers
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.classList.add('hidden');
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  try {
    const data = await apiFetch('/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    state.token = data.token;
    state.user = data.user;
    localStorage.setItem('mcp_admin_token', state.token);
    localStorage.setItem('mcp_admin_user', JSON.stringify(state.user));

    showToast('Authenticated successfully');
    initDashboard();
  } catch (err) {
    loginError.innerText = err.message;
    loginError.classList.remove('hidden');
  }
});

function handleLogout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem('mcp_admin_token');
  localStorage.removeItem('mcp_admin_user');
  dashboardView.classList.add('hidden');
  loginView.classList.remove('hidden');
}

logoutBtn.addEventListener('click', handleLogout);

// Tab Navigation
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    tab.classList.add('active');
    const targetId = tab.getAttribute('data-tab');
    document.getElementById(targetId).classList.add('active');

    if (targetId === 'audit-tab') loadAuditEvents();
    if (targetId === 'endpoints-tab') loadDiscoveryDocs();
  });
});

// Load Dashboard Overview & Stats
async function loadStats() {
  try {
    const data = await apiFetch('/admin/api/stats');
    if (data.stats) {
      statTotalClients.innerText = data.stats.totalClients;
      statActiveClients.innerText = data.stats.activeClients;
      statRevokedClients.innerText = data.stats.revokedClients;
      statTotalEvents.innerText = data.stats.totalEvents;
    }
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// Load and Render MCP Clients
async function loadClients() {
  try {
    const data = await apiFetch('/admin/api/clients');
    state.clients = data.clients || [];
    renderClients();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderClients() {
  if (state.clients.length === 0) {
    clientsTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-muted">
          No MCP servers registered yet. Click "Register New MCP" above to add your first server.
        </td>
      </tr>
    `;
    return;
  }

  clientsTableBody.innerHTML = state.clients.map(client => {
    const statusBadge = client.revoked
      ? `<span class="badge badge-danger">Revoked</span>`
      : `<span class="badge badge-success">Active</span>`;

    const actionButtons = client.revoked
      ? `<button class="btn btn-sm btn-success unrevoke-btn" data-id="${client.id}">Restore</button>`
      : `
        <button class="btn btn-sm btn-secondary gen-token-btn" data-id="${client.id}" title="Generate new Mode 2 static token">Static Token</button>
        <button class="btn btn-sm btn-danger revoke-btn" data-id="${client.id}">Revoke</button>
      `;

    const dateStr = new Date(client.created_at).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });

    return `
      <tr>
        <td>
          <strong>${escapeHtml(client.name)}</strong>
        </td>
        <td>
          <code class="font-mono text-muted">${escapeHtml(client.client_id)}</code>
        </td>
        <td>
          <code class="font-mono">${escapeHtml(client.audience)}</code>
        </td>
        <td>${statusBadge}</td>
        <td>${dateStr}</td>
        <td class="text-right">
          ${actionButtons}
        </td>
      </tr>
    `;
  }).join('');

  // Attach Event Listeners to Action Buttons
  document.querySelectorAll('.revoke-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.target.getAttribute('data-id');
      if (confirm('Are you sure you want to revoke this MCP server? All issued tokens will be immediately rejected!')) {
        try {
          await apiFetch(`/admin/api/clients/${id}/revoke`, { method: 'POST' });
          showToast('MCP Server revoked immediately');
          loadClients();
          loadStats();
        } catch (err) {
          showToast(err.message, 'error');
        }
      }
    });
  });

  document.querySelectorAll('.unrevoke-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.target.getAttribute('data-id');
      try {
        await apiFetch(`/admin/api/clients/${id}/unrevoke`, { method: 'POST' });
        showToast('MCP Server restored');
        loadClients();
        loadStats();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  });

  document.querySelectorAll('.gen-token-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.target.getAttribute('data-id');
      const client = state.clients.find(c => c.id === id);
      if (!client) return;

      try {
        const data = await apiFetch(`/admin/api/clients/${id}/static-token`, {
          method: 'POST',
          body: JSON.stringify({ days: 90 })
        });
        showToast('New static token generated');
        openSecretModal({
          client,
          clientSecret: '(Unchanged — original secret preserved)',
          staticToken: data.staticToken
        });
        loadStats();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  });
}

// Load and Render Audit Events
async function loadAuditEvents() {
  try {
    const data = await apiFetch('/admin/api/audit?limit=50');
    state.events = data.events || [];
    renderAuditEvents();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

refreshAuditBtn.addEventListener('click', () => {
  loadAuditEvents();
  loadStats();
  showToast('Audit log updated');
});

function renderAuditEvents() {
  if (state.events.length === 0) {
    auditTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-muted">No audit events recorded yet.</td>
      </tr>
    `;
    return;
  }

  auditTableBody.innerHTML = state.events.map(ev => {
    let typeBadge = `<span class="badge badge-info">${ev.event_type}</span>`;
    if (ev.event_type === 'issued') typeBadge = `<span class="badge badge-success">issued</span>`;
    if (ev.event_type === 'failed') typeBadge = `<span class="badge badge-danger">failed</span>`;
    if (ev.event_type === 'revoked') typeBadge = `<span class="badge badge-danger">revoked</span>`;
    if (ev.event_type === 'registered') typeBadge = `<span class="badge badge-warning">registered</span>`;

    const timestamp = new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric' });

    let detailsDisplay = ev.details || '';
    try {
      if (detailsDisplay.startsWith('{') || detailsDisplay.startsWith('[')) {
        const parsed = JSON.parse(detailsDisplay);
        detailsDisplay = Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join(', ');
      }
    } catch {}

    return `
      <tr>
        <td class="font-mono text-muted" style="white-space: nowrap;">${timestamp}</td>
        <td>${typeBadge}</td>
        <td><code class="font-mono">${escapeHtml(ev.client_id || '—')}</code></td>
        <td><code class="font-mono">${escapeHtml(ev.audience || '—')}</code></td>
        <td><span class="badge badge-pulse">${escapeHtml(ev.mode || 'standard')}</span></td>
        <td class="text-muted" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsDisplay)}">
          ${escapeHtml(detailsDisplay || '—')}
        </td>
      </tr>
    `;
  }).join('');
}

// Load Discovery Previews
async function loadDiscoveryDocs() {
  try {
    const metaRes = await fetch('/.well-known/oauth-authorization-server');
    const metaJson = await metaRes.json();
    metadataPreview.innerText = JSON.stringify(metaJson, null, 2);

    const jwksRes = await fetch('/.well-known/jwks.json');
    const jwksJson = await jwksRes.json();
    jwksPreview.innerText = JSON.stringify(jwksJson, null, 2);
  } catch (err) {
    console.error('Failed to load discovery docs:', err);
  }
}

// Modal Handlers
openCreateModalBtn.addEventListener('click', () => {
  createMcpForm.reset();
  document.getElementById('new-generate-static').checked = true;
  createModal.classList.remove('hidden');
});

document.querySelectorAll('.modal-close-btn, .modal-cancel-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    createModal.classList.add('hidden');
    secretModal.classList.add('hidden');
  });
});

createMcpForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('new-mcp-name').value.trim();
  const audience = document.getElementById('new-mcp-audience').value.trim();
  const rawRedirects = document.getElementById('new-mcp-redirects').value.trim();
  const generateStaticToken = document.getElementById('new-generate-static').checked;

  const allowedRedirectUris = rawRedirects
    ? rawRedirects.split(',').map(s => s.trim()).filter(Boolean)
    : [];

  try {
    const data = await apiFetch('/admin/api/clients', {
      method: 'POST',
      body: JSON.stringify({
        name,
        audience,
        allowedRedirectUris,
        generateStaticToken
      })
    });

    createModal.classList.add('hidden');
    showToast('MCP Server registered successfully');
    loadClients();
    loadStats();

    // Show One-Time Secret Modal
    openSecretModal({
      client: data.client,
      clientSecret: data.clientSecret,
      staticToken: data.staticToken
    });
  } catch (err) {
    showToast(err.message, 'error');
  }
});

function openSecretModal({ client, clientSecret, staticToken }) {
  document.getElementById('reveal-audience').innerText = `${client.name} (${client.audience})`;
  document.getElementById('reveal-client-id').value = client.client_id;
  document.getElementById('reveal-secret').value = clientSecret;

  const staticSection = document.getElementById('reveal-static-token-section');
  const tokenVal = staticToken ? staticToken.token : '';

  if (staticToken) {
    staticSection.classList.remove('hidden');
    document.getElementById('reveal-static-token').value = tokenVal;
  } else {
    staticSection.classList.add('hidden');
  }

  // Generate Ready-to-paste MCP config snippet for Claude / Cursor / Gemini
  const mcpConfigSnippet = {
    mcpServers: {
      [client.audience]: {
        command: "node",
        args: ["./dist/server.js"],
        env: {
          MCP_AUTH_JWKS_URI: `${window.location.origin}/.well-known/jwks.json`,
          MCP_AUTH_AUDIENCE: client.audience
        },
        headers: {
          "Authorization": `Bearer ${tokenVal || '<OAUTH_OR_STATIC_TOKEN>'}`
        }
      }
    }
  };

  document.getElementById('reveal-mcp-config').innerText = JSON.stringify(mcpConfigSnippet, null, 2);
  secretModal.classList.remove('hidden');
}

// Copy to Clipboard Utility
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('copy-btn') || e.target.closest('.copy-btn')) {
    const btn = e.target.classList.contains('copy-btn') ? e.target : e.target.closest('.copy-btn');
    const targetId = btn.getAttribute('data-target');
    const targetEl = document.getElementById(targetId);

    let textToCopy = '';
    if (targetEl.tagName === 'INPUT' || targetEl.tagName === 'TEXTAREA') {
      textToCopy = targetEl.value;
    } else {
      textToCopy = targetEl.innerText;
    }

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        showToast('Copied to clipboard!');
      });
    } else {
      // Fallback
      const textArea = document.createElement('textarea');
      textArea.value = textToCopy;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      textArea.remove();
      showToast('Copied to clipboard!');
    }
  }
});

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Initialize Application
function initDashboard() {
  if (!state.token) {
    loginView.classList.remove('hidden');
    dashboardView.classList.add('hidden');
    return;
  }

  loginView.classList.add('hidden');
  dashboardView.classList.remove('hidden');
  if (state.user) {
    navUsername.innerText = state.user.username;
  }

  loadStats();
  loadClients();
  loadDiscoveryDocs();
}

// On Page Load
initDashboard();
