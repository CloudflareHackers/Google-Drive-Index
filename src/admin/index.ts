/**
 * Admin Panel Module - Full CRUD for D1 configuration
 * @version 3.1.0
 */

import { config, adminConfig } from '../config';
import { encryptString, decryptString, generateIntegrity, verifyIntegrity } from '../utils/crypto';
import { parseCookies, buildCookie, jsonResponse, htmlResponse } from '../utils/helpers';
import { getAllDrives } from '../services/drive';
import type { Env, AdminStats } from '../types';

const ADMIN_SESSION_NAME = 'admin_session';

// ============================================================================
// Auth helpers
// ============================================================================

async function generateAdminToken(username: string): Promise<string> {
  const expiry = Date.now() + adminConfig.sessionDuration;
  const data = `${username}|${expiry}`;
  const hash = await generateIntegrity(data, adminConfig.sessionSecret);
  return `${await encryptString(data)}|${hash}`;
}

async function verifyAdminToken(token: string): Promise<boolean> {
  try {
    const [encrypted, hash] = token.split('|');
    const data = await decryptString(encrypted);
    const [_username, expiryStr] = data.split('|');
    if (parseInt(expiryStr) < Date.now()) return false;
    return await verifyIntegrity(data, hash, adminConfig.sessionSecret);
  } catch {
    return false;
  }
}

export async function isAdminAuthenticated(request: Request): Promise<boolean> {
  if (!adminConfig.enabled) return false;
  const cookies = parseCookies(request.headers.get('cookie'));
  const token = cookies[ADMIN_SESSION_NAME];
  if (!token) return false;
  return verifyAdminToken(token);
}

async function getAdminCredentials(env?: Env): Promise<{ username: string; password: string }> {
  if (env?.DB) {
    try {
      const dbUsername = await env.DB.prepare("SELECT value FROM config WHERE key = 'admin.username' LIMIT 1").first<{ value: string }>();
      const dbPassword = await env.DB.prepare("SELECT value FROM config WHERE key = 'admin.password' LIMIT 1").first<{ value: string }>();
      if (dbUsername?.value && dbPassword?.value) {
        return { username: dbUsername.value, password: dbPassword.value };
      }
    } catch { /* fall through */ }
  }
  return { username: adminConfig.username, password: adminConfig.password };
}

export async function handleAdminLogin(request: Request, env?: Env): Promise<Response> {
  const formData = await request.formData();
  const username = formData.get('username') as string;
  const password = formData.get('password') as string;
  const creds = await getAdminCredentials(env);
  if (username !== creds.username || password !== creds.password) {
    return jsonResponse({ ok: false, error: 'Invalid credentials' }, 401);
  }
  const token = await generateAdminToken(username);
  return jsonResponse({ ok: true }, 200, {
    'Set-Cookie': buildCookie(ADMIN_SESSION_NAME, token, { path: '/admin', httpOnly: true, secure: true, sameSite: 'Strict' })
  });
}

export function handleAdminLogout(): Response {
  return new Response(null, {
    status: 302,
    headers: { 'Set-Cookie': buildCookie(ADMIN_SESSION_NAME, '', { path: '/admin', maxAge: 0 }), 'Location': '/admin' }
  });
}

// ============================================================================
// API handlers
// ============================================================================

async function apiGetDrives(env: Env): Promise<Response> {
  const result = await env.DB.prepare('SELECT * FROM drives ORDER BY order_index').all();
  return jsonResponse({ drives: result.results || [] });
}

async function apiAddDrive(body: any, env: Env): Promise<Response> {
  if (!body.drive_id || !body.name) return jsonResponse({ error: 'drive_id and name required' }, 400);
  const maxOrder = await env.DB.prepare('SELECT MAX(order_index) as mx FROM drives').first<{ mx: number }>();
  const order = (maxOrder?.mx ?? -1) + 1;
  await env.DB.prepare('INSERT INTO drives (drive_id, name, order_index, protect_file_link, enabled) VALUES (?, ?, ?, ?, 1)')
    .bind(body.drive_id, body.name, order, body.protect_file_link ? 1 : 0).run();
  return jsonResponse({ ok: true });
}

async function apiUpdateDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('UPDATE drives SET name = ?, drive_id = ?, protect_file_link = ?, enabled = ? WHERE id = ?')
    .bind(body.name, body.drive_id, body.protect_file_link ? 1 : 0, body.enabled ? 1 : 0, body.id).run();
  return jsonResponse({ ok: true });
}

async function apiDeleteDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('DELETE FROM drives WHERE id = ?').bind(body.id).run();
  return jsonResponse({ ok: true });
}

async function apiReorderDrives(body: any, env: Env): Promise<Response> {
  if (!Array.isArray(body.order)) return jsonResponse({ error: 'order array required' }, 400);
  const stmts = body.order.map((id: number, idx: number) =>
    env.DB.prepare('UPDATE drives SET order_index = ? WHERE id = ?').bind(idx, id)
  );
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

async function apiGetConfig(env: Env): Promise<Response> {
  const result = await env.DB.prepare('SELECT key, value FROM config ORDER BY key').all<{ key: string; value: string }>();
  return jsonResponse({ config: result.results || [] });
}

async function apiSetConfig(body: any, env: Env): Promise<Response> {
  if (!body.key) return jsonResponse({ error: 'key required' }, 400);
  await env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))')
    .bind(body.key, body.value ?? '').run();
  return jsonResponse({ ok: true });
}

async function apiDeleteConfig(body: any, env: Env): Promise<Response> {
  if (!body.key) return jsonResponse({ error: 'key required' }, 400);
  await env.DB.prepare('DELETE FROM config WHERE key = ?').bind(body.key).run();
  return jsonResponse({ ok: true });
}

async function apiBulkSetConfig(body: any, env: Env): Promise<Response> {
  if (!body.items || !Array.isArray(body.items)) return jsonResponse({ error: 'items array required' }, 400);
  const stmts = body.items.map((item: { key: string; value: string }) =>
    env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(item.key, item.value ?? '')
  );
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

async function apiGetServiceAccounts(env: Env): Promise<Response> {
  const result = await env.DB.prepare('SELECT id, name, enabled FROM service_accounts ORDER BY id').all();
  return jsonResponse({ accounts: result.results || [] });
}

async function apiAddServiceAccount(body: any, env: Env): Promise<Response> {
  if (!body.json_data) return jsonResponse({ error: 'json_data required' }, 400);
  try {
    const sa = JSON.parse(body.json_data);
    await env.DB.prepare('INSERT INTO service_accounts (name, json_data, enabled) VALUES (?, ?, 1)')
      .bind(sa.client_email || body.name || 'Service Account', body.json_data).run();
    return jsonResponse({ ok: true });
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }
}

async function apiDeleteServiceAccount(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('DELETE FROM service_accounts WHERE id = ?').bind(body.id).run();
  return jsonResponse({ ok: true });
}

// ============================================================================
// Main request handler
// ============================================================================

export async function handleAdminRequest(request: Request, env?: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (!path.startsWith('/admin')) return null;
  if (!adminConfig.enabled) return htmlResponse('Admin panel disabled', 404);

  const authenticated = await isAdminAuthenticated(request);

  // Login page
  if (path === '/admin' || path === '/admin/') {
    return htmlResponse(authenticated ? getAdminDashboardHTML() : getAdminLoginHTML());
  }
  if (path === '/admin/login' && request.method === 'POST') {
    return handleAdminLogin(request, env);
  }
  if (path === '/admin/logout') {
    return handleAdminLogout();
  }

  // All API routes require auth
  if (!authenticated) return jsonResponse({ error: 'Unauthorized' }, 401);
  if (!env?.DB) return jsonResponse({ error: 'D1 not configured' }, 500);

  // API routes
  if (request.method === 'GET') {
    switch (path) {
      case '/admin/api/drives': return apiGetDrives(env);
      case '/admin/api/config': return apiGetConfig(env);
      case '/admin/api/service-accounts': return apiGetServiceAccounts(env);
    }
  }

  if (request.method === 'POST') {
    const body = await request.json() as any;
    switch (path) {
      case '/admin/api/drives/add': return apiAddDrive(body, env);
      case '/admin/api/drives/update': return apiUpdateDrive(body, env);
      case '/admin/api/drives/delete': return apiDeleteDrive(body, env);
      case '/admin/api/drives/reorder': return apiReorderDrives(body, env);
      case '/admin/api/config/set': return apiSetConfig(body, env);
      case '/admin/api/config/delete': return apiDeleteConfig(body, env);
      case '/admin/api/config/bulk': return apiBulkSetConfig(body, env);
      case '/admin/api/service-accounts/add': return apiAddServiceAccount(body, env);
      case '/admin/api/service-accounts/delete': return apiDeleteServiceAccount(body, env);
    }
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

// ============================================================================
// HTML Templates
// ============================================================================

function getAdminLoginHTML(): string {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{min-height:100vh;display:flex;align-items:center;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460)}.card{border:none;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.3)}</style>
</head><body>
<div class="container"><div class="row justify-content-center"><div class="col-md-4">
<div class="card"><div class="card-body p-4">
<h4 class="text-center mb-4"><i class="bi bi-shield-lock"></i> Admin Login</h4>
<div id="error" class="alert alert-danger d-none"></div>
<form id="loginForm">
<div class="mb-3"><label class="form-label">Username</label><input type="text" class="form-control" name="username" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>
<button type="submit" class="btn btn-primary w-100">Sign In</button>
</form></div></div></div></div></div>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<script>
document.getElementById('loginForm').onsubmit=async(e)=>{
  e.preventDefault();
  const btn=e.target.querySelector('button');btn.disabled=true;btn.textContent='Signing in...';
  try{const r=await fetch('/admin/login',{method:'POST',body:new FormData(e.target)});const d=await r.json();
  if(d.ok)location.reload();else{document.getElementById('error').textContent=d.error||'Login failed';document.getElementById('error').classList.remove('d-none')}}
  finally{btn.disabled=false;btn.textContent='Sign In'}
};
</script></body></html>`;
}

function getAdminDashboardHTML(): string {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<style>
body{background:#f8f9fa}.sidebar{background:#212529;min-height:100vh;padding-top:1rem}
.sidebar .nav-link{color:#adb5bd;padding:.6rem 1rem;border-radius:6px;margin:2px 8px}
.sidebar .nav-link:hover,.sidebar .nav-link.active{color:#fff;background:rgba(255,255,255,.1)}
.sidebar .nav-link i{width:20px;margin-right:8px}
.card{border:none;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.stat-card{transition:transform .2s}.stat-card:hover{transform:translateY(-2px)}
.table th{font-weight:600;font-size:.85rem;text-transform:uppercase;color:#6c757d}
.badge-enabled{background:#198754}.badge-disabled{background:#dc3545}
#toast-container{position:fixed;top:20px;right:20px;z-index:9999}
</style>
</head><body>
<div id="toast-container"></div>
<div class="d-flex">
<!-- Sidebar -->
<div class="sidebar d-flex flex-column" style="width:240px">
  <div class="px-3 mb-3"><h5 class="text-white mb-0"><i class="bi bi-gear-fill"></i> Admin</h5><small class="text-muted">Google Drive Index</small></div>
  <nav class="nav flex-column flex-grow-1">
    <a class="nav-link active" href="#" onclick="showTab('dashboard')"><i class="bi bi-speedometer2"></i>Dashboard</a>
    <a class="nav-link" href="#" onclick="showTab('drives')"><i class="bi bi-hdd-stack"></i>Drives</a>
    <a class="nav-link" href="#" onclick="showTab('config')"><i class="bi bi-sliders"></i>Configuration</a>
    <a class="nav-link" href="#" onclick="showTab('service-accounts')"><i class="bi bi-key"></i>Service Accounts</a>
    <a class="nav-link" href="#" onclick="showTab('security')"><i class="bi bi-shield-check"></i>Security</a>
  </nav>
  <div class="px-3 pb-3 mt-auto">
    <a href="/" class="btn btn-outline-light btn-sm w-100 mb-2" target="_blank"><i class="bi bi-box-arrow-up-right"></i> View Site</a>
    <a href="/admin/logout" class="btn btn-outline-danger btn-sm w-100"><i class="bi bi-box-arrow-left"></i> Logout</a>
  </div>
</div>

<!-- Main content -->
<div class="flex-grow-1 p-4" style="min-height:100vh">

<!-- Dashboard Tab -->
<div id="tab-dashboard">
  <h4 class="mb-4">Dashboard</h4>
  <div class="row g-3 mb-4" id="stats-row"></div>
  <div class="card"><div class="card-header"><h6 class="mb-0">Quick Overview</h6></div>
  <div class="card-body" id="overview-content"><div class="text-center py-3"><div class="spinner-border spinner-border-sm"></div> Loading...</div></div></div>
</div>

<!-- Drives Tab -->
<div id="tab-drives" class="d-none">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="mb-0">Drives</h4>
    <button class="btn btn-primary" onclick="showAddDriveModal()"><i class="bi bi-plus-lg"></i> Add Drive</button>
  </div>
  <div class="card"><div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead><tr><th>#</th><th>Name</th><th>Drive ID</th><th>Protected</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="drives-tbody"><tr><td colspan="6" class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></td></tr></tbody>
    </table>
  </div></div>
</div>

<!-- Config Tab -->
<div id="tab-config" class="d-none">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="mb-0">Configuration</h4>
    <div>
      <button class="btn btn-outline-primary btn-sm" onclick="showAddConfigModal()"><i class="bi bi-plus-lg"></i> Add Key</button>
      <button class="btn btn-primary btn-sm ms-2" onclick="saveAllConfig()"><i class="bi bi-save"></i> Save All</button>
    </div>
  </div>
  <div id="config-sections"></div>
</div>

<!-- Service Accounts Tab -->
<div id="tab-service-accounts" class="d-none">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="mb-0">Service Accounts</h4>
    <button class="btn btn-primary" onclick="showAddSAModal()"><i class="bi bi-plus-lg"></i> Add Service Account</button>
  </div>
  <div class="card"><div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead><tr><th>#</th><th>Name</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="sa-tbody"><tr><td colspan="4" class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></td></tr></tbody>
    </table>
  </div></div>
</div>

<!-- Security Tab -->
<div id="tab-security" class="d-none">
  <h4 class="mb-4">Security Settings</h4>
  <div class="card mb-3"><div class="card-header"><h6 class="mb-0">Admin Credentials</h6></div>
  <div class="card-body">
    <div class="row g-3">
      <div class="col-md-6"><label class="form-label">Username</label><input type="text" class="form-control" id="sec-admin-user"></div>
      <div class="col-md-6"><label class="form-label">Password</label><input type="password" class="form-control" id="sec-admin-pass"></div>
    </div>
    <button class="btn btn-primary mt-3" onclick="saveAdminCreds()"><i class="bi bi-save"></i> Save Credentials</button>
  </div></div>
  <div class="card mb-3"><div class="card-header"><h6 class="mb-0">Blocked Regions</h6></div>
  <div class="card-body">
    <label class="form-label">Country Codes (comma-separated)</label>
    <input type="text" class="form-control" id="sec-blocked-regions" placeholder="e.g. CN, RU">
    <button class="btn btn-primary mt-3" onclick="saveSecurityConfig()"><i class="bi bi-save"></i> Save</button>
  </div></div>
  <div class="card"><div class="card-header"><h6 class="mb-0">Crypto Keys</h6></div>
  <div class="card-body">
    <div class="mb-3"><label class="form-label">Crypto Key</label><input type="text" class="form-control font-monospace" id="sec-crypto-key" readonly>
    <button class="btn btn-outline-secondary btn-sm mt-1" onclick="regenerateKey('crypto')"><i class="bi bi-arrow-repeat"></i> Regenerate</button></div>
    <div class="mb-3"><label class="form-label">HMAC Key</label><input type="text" class="form-control font-monospace" id="sec-hmac-key" readonly>
    <button class="btn btn-outline-secondary btn-sm mt-1" onclick="regenerateKey('hmac')"><i class="bi bi-arrow-repeat"></i> Regenerate</button></div>
  </div></div>
</div>

</div></div>

<!-- Modals -->
<div class="modal fade" id="driveModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title" id="driveModalTitle">Add Drive</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body">
  <input type="hidden" id="drive-edit-id">
  <div class="mb-3"><label class="form-label">Drive Name</label><input type="text" class="form-control" id="drive-name" placeholder="My Shared Drive"></div>
  <div class="mb-3"><label class="form-label">Drive / Folder ID</label><input type="text" class="form-control font-monospace" id="drive-id" placeholder="0ABCD..."></div>
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="drive-protect"><label class="form-check-label" for="drive-protect">Protect file links</label></div>
</div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="saveDrive()">Save</button></div>
</div></div></div>

<div class="modal fade" id="configModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Config Key</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body">
  <div class="mb-3"><label class="form-label">Key</label><input type="text" class="form-control font-monospace" id="new-config-key" placeholder="category.key_name"></div>
  <div class="mb-3"><label class="form-label">Value</label><input type="text" class="form-control" id="new-config-value"></div>
</div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addConfigKey()">Add</button></div>
</div></div></div>

<div class="modal fade" id="saModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Service Account</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body">
  <div class="mb-3"><label class="form-label">Service Account JSON</label>
  <textarea class="form-control font-monospace" id="sa-json" rows="10" placeholder='Paste service account JSON here...'></textarea></div>
</div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addServiceAccount()">Add</button></div>
</div></div></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
// State
let allConfig = [];
let allDrives = [];
let allSA = [];

// Toast helper
function toast(msg, type='success') {
  const id = 'toast-' + Date.now();
  document.getElementById('toast-container').insertAdjacentHTML('beforeend',
    '<div id="'+id+'" class="toast show align-items-center text-bg-'+type+' border-0 mb-2" role="alert"><div class="d-flex"><div class="toast-body">'+msg+'</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>');
  setTimeout(()=>{const el=document.getElementById(id);if(el)el.remove()},3000);
}

// API helper
async function api(path, body) {
  const opts = body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {};
  const r = await fetch('/admin/api/'+path, opts);
  const d = await r.json();
  if(d.error) throw new Error(d.error);
  return d;
}

// Tab switching
function showTab(name) {
  document.querySelectorAll('[id^="tab-"]').forEach(el=>el.classList.add('d-none'));
  document.getElementById('tab-'+name).classList.remove('d-none');
  document.querySelectorAll('.sidebar .nav-link').forEach(el=>el.classList.remove('active'));
  event.target.closest('.nav-link').classList.add('active');
  if(name==='drives') loadDrives();
  if(name==='config') loadConfig();
  if(name==='service-accounts') loadServiceAccounts();
  if(name==='security') loadSecurity();
  if(name==='dashboard') loadDashboard();
}

// ============== Dashboard ==============
async function loadDashboard() {
  try {
    const [dData, cData, saData] = await Promise.all([api('drives'), api('config'), api('service-accounts')]);
    allDrives = dData.drives; allConfig = cData.config; allSA = saData.accounts;
    
    const siteName = allConfig.find(c=>c.key==='site.name')?.value || 'Google Drive Index';
    const dlMode = allConfig.find(c=>c.key==='site.download_mode')?.value || 'path';
    const loginEnabled = allConfig.find(c=>c.key==='auth.enable_login')?.value === 'true';
    
    document.getElementById('stats-row').innerHTML = [
      statCard('bi-hdd-stack','Drives',allDrives.length,'primary'),
      statCard('bi-key','Service Accounts',allSA.length,'warning'),
      statCard('bi-sliders','Config Keys',allConfig.length,'info'),
      statCard('bi-shield-check','Login',loginEnabled?'Enabled':'Disabled',loginEnabled?'success':'secondary'),
    ].join('');
    
    document.getElementById('overview-content').innerHTML =
      '<div class="row"><div class="col-md-6"><strong>Site Name:</strong> '+siteName+'</div>'+
      '<div class="col-md-6"><strong>Download Mode:</strong> '+dlMode+'</div></div>'+
      '<hr><h6>Drives</h6>' +
      (allDrives.length ? '<ul class="list-group list-group-flush">'+allDrives.map(d=>'<li class="list-group-item d-flex justify-content-between"><span>'+d.name+'</span><code>'+d.drive_id+'</code></li>').join('')+'</ul>' : '<p class="text-muted">No drives configured</p>');
  } catch(e) { document.getElementById('overview-content').innerHTML = '<div class="alert alert-danger">'+e.message+'</div>'; }
}

function statCard(icon,label,value,color) {
  return '<div class="col-md-3"><div class="card stat-card border-start border-4 border-'+color+'"><div class="card-body py-3"><div class="d-flex align-items-center"><div class="flex-grow-1"><div class="text-muted small">'+label+'</div><div class="h4 mb-0">'+value+'</div></div><i class="bi '+icon+' fs-2 text-'+color+'"></i></div></div></div></div>';
}

// ============== Drives ==============
async function loadDrives() {
  try {
    const data = await api('drives');
    allDrives = data.drives;
    const tbody = document.getElementById('drives-tbody');
    if(!allDrives.length) { tbody.innerHTML='<tr><td colspan="6" class="text-center text-muted py-4">No drives configured. Click "Add Drive" to get started.</td></tr>'; return; }
    tbody.innerHTML = allDrives.map((d,i) =>
      '<tr><td>'+i+'</td><td><strong>'+esc(d.name)+'</strong></td><td><code class="small">'+esc(d.drive_id)+'</code></td>'+
      '<td>'+(d.protect_file_link?'<span class="badge bg-warning">Yes</span>':'<span class="badge bg-secondary">No</span>')+'</td>'+
      '<td>'+(d.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Disabled</span>')+'</td>'+
      '<td><button class="btn btn-sm btn-outline-primary me-1" onclick="editDrive('+d.id+')"><i class="bi bi-pencil"></i></button>'+
      '<button class="btn btn-sm btn-outline-danger" onclick="deleteDrive('+d.id+',\\''+esc(d.name)+'\\')"><i class="bi bi-trash"></i></button></td></tr>'
    ).join('');
  } catch(e) { toast(e.message,'danger'); }
}

function showAddDriveModal() {
  document.getElementById('driveModalTitle').textContent='Add Drive';
  document.getElementById('drive-edit-id').value='';
  document.getElementById('drive-name').value='';
  document.getElementById('drive-id').value='';
  document.getElementById('drive-protect').checked=false;
  new bootstrap.Modal(document.getElementById('driveModal')).show();
}

function editDrive(id) {
  const d=allDrives.find(x=>x.id===id);if(!d)return;
  document.getElementById('driveModalTitle').textContent='Edit Drive';
  document.getElementById('drive-edit-id').value=d.id;
  document.getElementById('drive-name').value=d.name;
  document.getElementById('drive-id').value=d.drive_id;
  document.getElementById('drive-protect').checked=!!d.protect_file_link;
  new bootstrap.Modal(document.getElementById('driveModal')).show();
}

async function saveDrive() {
  const editId=document.getElementById('drive-edit-id').value;
  const data={name:document.getElementById('drive-name').value,drive_id:document.getElementById('drive-id').value,protect_file_link:document.getElementById('drive-protect').checked};
  try {
    if(editId){await api('drives/update',{...data,id:parseInt(editId),enabled:true});}
    else{await api('drives/add',data);}
    bootstrap.Modal.getInstance(document.getElementById('driveModal')).hide();
    toast(editId?'Drive updated':'Drive added');loadDrives();
  } catch(e){toast(e.message,'danger');}
}

async function deleteDrive(id,name) {
  if(!confirm('Delete drive "'+name+'"?'))return;
  try{await api('drives/delete',{id});toast('Drive deleted');loadDrives();}catch(e){toast(e.message,'danger');}
}

// ============== Config ==============
async function loadConfig() {
  try {
    const data = await api('config');
    allConfig = data.config;
    const groups = {};
    allConfig.forEach(c => {
      const cat = c.key.split('.')[0] || 'other';
      if(!groups[cat]) groups[cat]=[];
      groups[cat].push(c);
    });
    const sections = Object.keys(groups).sort().map(cat =>
      '<div class="card mb-3"><div class="card-header d-flex justify-content-between align-items-center"><h6 class="mb-0 text-capitalize">'+cat+'</h6><span class="badge bg-secondary">'+groups[cat].length+'</span></div>'+
      '<div class="card-body p-0"><table class="table table-sm mb-0"><tbody>'+
      groups[cat].map(c =>
        '<tr><td style="width:35%"><code>'+esc(c.key)+'</code></td>'+
        '<td><input type="text" class="form-control form-control-sm config-input" data-key="'+esc(c.key)+'" value="'+esc(c.value)+'"></td>'+
        '<td style="width:60px"><button class="btn btn-sm btn-outline-danger" onclick="deleteConfigKey(\\''+esc(c.key)+'\\')"><i class="bi bi-trash"></i></button></td></tr>'
      ).join('')+'</tbody></table></div></div>'
    ).join('');
    document.getElementById('config-sections').innerHTML = sections || '<div class="text-muted text-center py-4">No configuration keys found.</div>';
  } catch(e) { toast(e.message,'danger'); }
}

function showAddConfigModal() {
  document.getElementById('new-config-key').value='';
  document.getElementById('new-config-value').value='';
  new bootstrap.Modal(document.getElementById('configModal')).show();
}

async function addConfigKey() {
  const key=document.getElementById('new-config-key').value.trim();
  const value=document.getElementById('new-config-value').value;
  if(!key){toast('Key is required','warning');return;}
  try{await api('config/set',{key,value});bootstrap.Modal.getInstance(document.getElementById('configModal')).hide();toast('Config key added');loadConfig();}catch(e){toast(e.message,'danger');}
}

async function deleteConfigKey(key) {
  if(!confirm('Delete config key "'+key+'"?'))return;
  try{await api('config/delete',{key});toast('Deleted');loadConfig();}catch(e){toast(e.message,'danger');}
}

async function saveAllConfig() {
  const inputs=document.querySelectorAll('.config-input');
  const items=[];
  inputs.forEach(el=>{items.push({key:el.dataset.key,value:el.value});});
  try{await api('config/bulk',{items});toast('All configuration saved!');}catch(e){toast(e.message,'danger');}
}

// ============== Service Accounts ==============
async function loadServiceAccounts() {
  try {
    const data = await api('service-accounts');
    allSA = data.accounts;
    const tbody = document.getElementById('sa-tbody');
    if(!allSA.length){tbody.innerHTML='<tr><td colspan="4" class="text-center text-muted py-4">No service accounts. Click "Add Service Account" to add one.</td></tr>';return;}
    tbody.innerHTML = allSA.map((sa,i) =>
      '<tr><td>'+(i+1)+'</td><td>'+esc(sa.name)+'</td>'+
      '<td>'+(sa.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Disabled</span>')+'</td>'+
      '<td><button class="btn btn-sm btn-outline-danger" onclick="deleteSA('+sa.id+',\\''+esc(sa.name)+'\\')"><i class="bi bi-trash"></i></button></td></tr>'
    ).join('');
  } catch(e){toast(e.message,'danger');}
}

function showAddSAModal() {
  document.getElementById('sa-json').value='';
  new bootstrap.Modal(document.getElementById('saModal')).show();
}

async function addServiceAccount() {
  const json=document.getElementById('sa-json').value.trim();
  if(!json){toast('JSON is required','warning');return;}
  try{JSON.parse(json);}catch{toast('Invalid JSON','danger');return;}
  try{await api('service-accounts/add',{json_data:json});bootstrap.Modal.getInstance(document.getElementById('saModal')).hide();toast('Service account added');loadServiceAccounts();}catch(e){toast(e.message,'danger');}
}

async function deleteSA(id,name) {
  if(!confirm('Delete service account "'+name+'"?'))return;
  try{await api('service-accounts/delete',{id});toast('Deleted');loadServiceAccounts();}catch(e){toast(e.message,'danger');}
}

// ============== Security ==============
async function loadSecurity() {
  try {
    const data = await api('config');
    allConfig = data.config;
    const get=k=>(allConfig.find(c=>c.key===k)||{}).value||'';
    document.getElementById('sec-admin-user').value=get('admin.username');
    document.getElementById('sec-admin-pass').value=get('admin.password');
    document.getElementById('sec-blocked-regions').value=get('security.blocked_regions');
    document.getElementById('sec-crypto-key').value=get('security.crypto_key');
    document.getElementById('sec-hmac-key').value=get('security.hmac_key');
  } catch(e){toast(e.message,'danger');}
}

async function saveAdminCreds() {
  const u=document.getElementById('sec-admin-user').value.trim();
  const p=document.getElementById('sec-admin-pass').value;
  if(!u||!p){toast('Both fields required','warning');return;}
  try{await api('config/bulk',{items:[{key:'admin.username',value:u},{key:'admin.password',value:p}]});toast('Admin credentials saved!');}catch(e){toast(e.message,'danger');}
}

async function saveSecurityConfig() {
  const regions=document.getElementById('sec-blocked-regions').value;
  try{await api('config/set',{key:'security.blocked_regions',value:regions});toast('Security config saved!');}catch(e){toast(e.message,'danger');}
}

async function regenerateKey(type) {
  if(!confirm('Regenerate '+type+' key? This will invalidate existing encrypted data.'))return;
  const arr=new Uint8Array(32);crypto.getRandomValues(arr);
  const hex=Array.from(arr,b=>b.toString(16).padStart(2,'0')).join('');
  const key=type==='crypto'?'security.crypto_key':'security.hmac_key';
  try{await api('config/set',{key,value:hex});toast(type+' key regenerated!');loadSecurity();}catch(e){toast(e.message,'danger');}
}

// Escape HTML
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// Init
loadDashboard();
</script></body></html>`;
}
