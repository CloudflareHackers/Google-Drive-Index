/**
 * Admin Panel Module - Full CRUD for D1 configuration
 * @version 3.2.0
 */

import { config, adminConfig } from '../config';
import { encryptString, decryptString, generateIntegrity, verifyIntegrity } from '../utils/crypto';
import { parseCookies, buildCookie, jsonResponse, htmlResponse } from '../utils/helpers';
import { getAllDrives, getAccessToken } from '../services/drive';
import type { Env } from '../types';

const ADMIN_SESSION_NAME = 'admin_session';

// Sensitive keys that should never be exposed in API responses
const SENSITIVE_KEYS = [
  'admin.password', 'admin.username',
  'auth.client_id', 'auth.client_secret', 'auth.refresh_token',
  'security.crypto_key', 'security.hmac_key',
  'google_login.client_id', 'google_login.client_secret',
];

// Keys to hide from the general config tab (managed in dedicated tabs)
const HIDDEN_FROM_CONFIG = [
  ...SENSITIVE_KEYS,
  'security.blocked_regions', 'security.blocked_asn',
  'setup.completed',
];

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
  } catch { return false; }
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
      const u = await env.DB.prepare("SELECT value FROM config WHERE key='admin.username'").first<{value:string}>();
      const p = await env.DB.prepare("SELECT value FROM config WHERE key='admin.password'").first<{value:string}>();
      if (u?.value && p?.value) return { username: u.value, password: p.value };
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
  const maxOrder = await env.DB.prepare('SELECT MAX(order_index) as mx FROM drives').first<{mx:number}>();
  await env.DB.prepare('INSERT INTO drives (drive_id, name, order_index, protect_file_link, enabled) VALUES (?, ?, ?, ?, 1)')
    .bind(body.drive_id, body.name, (maxOrder?.mx ?? -1) + 1, body.protect_file_link ? 1 : 0).run();
  return jsonResponse({ ok: true });
}

async function apiUpdateDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('UPDATE drives SET name=?, drive_id=?, protect_file_link=?, enabled=? WHERE id=?')
    .bind(body.name, body.drive_id, body.protect_file_link ? 1 : 0, body.enabled ? 1 : 0, body.id).run();
  return jsonResponse({ ok: true });
}

async function apiDeleteDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('DELETE FROM drives WHERE id=?').bind(body.id).run();
  return jsonResponse({ ok: true });
}

// Config API - filters out sensitive/hidden keys
async function apiGetConfig(env: Env): Promise<Response> {
  const result = await env.DB.prepare('SELECT key, value FROM config ORDER BY key').all<{key:string;value:string}>();
  const filtered = (result.results || []).filter(c => !HIDDEN_FROM_CONFIG.includes(c.key));
  return jsonResponse({ config: filtered });
}

async function apiSetConfig(body: any, env: Env): Promise<Response> {
  if (!body.key) return jsonResponse({ error: 'key required' }, 400);
  await env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(body.key, body.value ?? '').run();
  return jsonResponse({ ok: true });
}

async function apiDeleteConfig(body: any, env: Env): Promise<Response> {
  if (!body.key) return jsonResponse({ error: 'key required' }, 400);
  await env.DB.prepare('DELETE FROM config WHERE key=?').bind(body.key).run();
  return jsonResponse({ ok: true });
}

async function apiBulkSetConfig(body: any, env: Env): Promise<Response> {
  if (!body.items || !Array.isArray(body.items)) return jsonResponse({ error: 'items array required' }, 400);
  const stmts = body.items.map((item: {key:string;value:string}) =>
    env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(item.key, item.value ?? '')
  );
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

// Credentials API - only reports if set, never exposes values
async function apiGetCredentialsStatus(env: Env): Promise<Response> {
  const keys = ['auth.client_id','auth.client_secret','auth.refresh_token'];
  const results: Record<string,boolean> = {};
  for (const k of keys) {
    const r = await env.DB.prepare('SELECT value FROM config WHERE key=?').bind(k).first<{value:string}>();
    results[k] = !!(r?.value);
  }
  return jsonResponse({ credentials: results });
}

async function apiSaveCredentials(body: any, env: Env): Promise<Response> {
  const items: {key:string;value:string}[] = [];
  if (body.client_id !== undefined) items.push({key:'auth.client_id', value:body.client_id});
  if (body.client_secret !== undefined) items.push({key:'auth.client_secret', value:body.client_secret});
  if (body.refresh_token !== undefined) items.push({key:'auth.refresh_token', value:body.refresh_token});
  if (!items.length) return jsonResponse({ error: 'No credentials provided' }, 400);
  const stmts = items.map(i => env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(i.key, i.value));
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

// Google Login API
async function apiGetGoogleLoginStatus(env: Env): Promise<Response> {
  const keys = ['google_login.client_id','google_login.client_secret','auth.enable_social_login'];
  const results: Record<string,any> = {};
  for (const k of keys) {
    const r = await env.DB.prepare('SELECT value FROM config WHERE key=?').bind(k).first<{value:string}>();
    results[k] = k === 'auth.enable_social_login' ? r?.value === 'true' : !!(r?.value);
  }
  return jsonResponse(results);
}

async function apiSaveGoogleLogin(body: any, env: Env): Promise<Response> {
  const items: {key:string;value:string}[] = [];
  if (body.client_id !== undefined) items.push({key:'google_login.client_id', value:body.client_id});
  if (body.client_secret !== undefined) items.push({key:'google_login.client_secret', value:body.client_secret});
  if (body.enabled !== undefined) items.push({key:'auth.enable_social_login', value:body.enabled ? 'true' : 'false'});
  if (!items.length) return jsonResponse({ error: 'Nothing to save' }, 400);
  const stmts = items.map(i => env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(i.key, i.value));
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

// Security API
async function apiGetSecurityStatus(env: Env): Promise<Response> {
  const results: Record<string,any> = {};
  for (const k of ['admin.username','security.blocked_regions','security.blocked_asn']) {
    const r = await env.DB.prepare('SELECT value FROM config WHERE key=?').bind(k).first<{value:string}>();
    results[k] = r?.value || '';
  }
  // Only report if keys exist, not their values
  for (const k of ['security.crypto_key','security.hmac_key','admin.password']) {
    const r = await env.DB.prepare('SELECT value FROM config WHERE key=?').bind(k).first<{value:string}>();
    results[k+'_set'] = !!(r?.value);
  }
  return jsonResponse(results);
}

async function apiSaveSecurity(body: any, env: Env): Promise<Response> {
  const items: {key:string;value:string}[] = [];
  if (body.admin_username) items.push({key:'admin.username',value:body.admin_username});
  if (body.admin_password) items.push({key:'admin.password',value:body.admin_password});
  if (body.blocked_regions !== undefined) items.push({key:'security.blocked_regions',value:body.blocked_regions});
  if (body.blocked_asn !== undefined) items.push({key:'security.blocked_asn',value:body.blocked_asn});
  if (!items.length) return jsonResponse({ error: 'Nothing to save' }, 400);
  const stmts = items.map(i => env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(i.key, i.value));
  await env.DB.batch(stmts);
  return jsonResponse({ ok: true });
}

async function apiRegenerateKey(body: any, env: Env): Promise<Response> {
  const keyName = body.type === 'crypto' ? 'security.crypto_key' : 'security.hmac_key';
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const hex = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  await env.DB.prepare('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(keyName, hex).run();
  return jsonResponse({ ok: true });
}

// Fetch Drive root ID using API
async function apiFetchRootId(body: any, env: Env): Promise<Response> {
  try {
    // Get credentials from D1
    const clientId = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_id'").first<{value:string}>())?.value;
    const clientSecret = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_secret'").first<{value:string}>())?.value;
    const refreshToken = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.refresh_token'").first<{value:string}>())?.value;

    if (!clientId || !clientSecret || !refreshToken) {
      return jsonResponse({ error: 'OAuth credentials not configured' }, 400);
    }

    // Get access token
    const tokenRes = await fetch('https://www.googleapis.com/oauth2/v4/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${encodeURIComponent(refreshToken)}&grant_type=refresh_token`
    });
    const tokenData = await tokenRes.json() as any;
    if (!tokenData.access_token) return jsonResponse({ error: 'Failed to get access token' }, 500);

    const driveId = body.drive_id;
    if (!driveId) return jsonResponse({ error: 'drive_id required' }, 400);

    // If driveId is 'root', fetch the actual root folder ID
    if (driveId === 'root') {
      const res = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id,name', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const data = await res.json() as any;
      return jsonResponse({ root_id: data.id, name: data.name || 'My Drive' });
    }

    // For shared drives or folder IDs, try to get info
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${driveId}?fields=id,name,mimeType&supportsAllDrives=true`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const data = await res.json() as any;
    if (data.error) return jsonResponse({ error: data.error.message || 'Drive API error' }, 400);
    return jsonResponse({ root_id: data.id, name: data.name, mimeType: data.mimeType });
  } catch (e) {
    return jsonResponse({ error: (e as Error).message }, 500);
  }
}

// Service accounts
async function apiGetServiceAccounts(env: Env): Promise<Response> {
  const result = await env.DB.prepare('SELECT id, name, enabled FROM service_accounts ORDER BY id').all();
  return jsonResponse({ accounts: result.results || [] });
}

async function apiAddServiceAccount(body: any, env: Env): Promise<Response> {
  if (!body.json_data) return jsonResponse({ error: 'json_data required' }, 400);
  try {
    const sa = JSON.parse(body.json_data);
    await env.DB.prepare('INSERT INTO service_accounts (name, json_data, enabled) VALUES (?, ?, 1)')
      .bind(sa.client_email || 'Service Account', body.json_data).run();
    return jsonResponse({ ok: true });
  } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }
}

async function apiDeleteServiceAccount(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('DELETE FROM service_accounts WHERE id=?').bind(body.id).run();
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

  if (path === '/admin' || path === '/admin/') {
    return htmlResponse(authenticated ? getAdminDashboardHTML() : getAdminLoginHTML());
  }
  if (path === '/admin/login' && request.method === 'POST') return handleAdminLogin(request, env);
  if (path === '/admin/logout') return handleAdminLogout();

  if (!authenticated) return jsonResponse({ error: 'Unauthorized' }, 401);
  if (!env?.DB) return jsonResponse({ error: 'D1 not configured' }, 500);

  if (request.method === 'GET') {
    switch (path) {
      case '/admin/api/drives': return apiGetDrives(env);
      case '/admin/api/config': return apiGetConfig(env);
      case '/admin/api/credentials': return apiGetCredentialsStatus(env);
      case '/admin/api/google-login': return apiGetGoogleLoginStatus(env);
      case '/admin/api/security': return apiGetSecurityStatus(env);
      case '/admin/api/service-accounts': return apiGetServiceAccounts(env);
    }
  }
  if (request.method === 'POST') {
    const body = await request.json() as any;
    switch (path) {
      case '/admin/api/drives/add': return apiAddDrive(body, env);
      case '/admin/api/drives/update': return apiUpdateDrive(body, env);
      case '/admin/api/drives/delete': return apiDeleteDrive(body, env);
      case '/admin/api/drives/fetch-root': return apiFetchRootId(body, env);
      case '/admin/api/config/set': return apiSetConfig(body, env);
      case '/admin/api/config/delete': return apiDeleteConfig(body, env);
      case '/admin/api/config/bulk': return apiBulkSetConfig(body, env);
      case '/admin/api/credentials/save': return apiSaveCredentials(body, env);
      case '/admin/api/google-login/save': return apiSaveGoogleLogin(body, env);
      case '/admin/api/security/save': return apiSaveSecurity(body, env);
      case '/admin/api/security/regenerate-key': return apiRegenerateKey(body, env);
      case '/admin/api/service-accounts/add': return apiAddServiceAccount(body, env);
      case '/admin/api/service-accounts/delete': return apiDeleteServiceAccount(body, env);
    }
  }
  return jsonResponse({ error: 'Not found' }, 404);
}

// ============================================================================
// HTML
// ============================================================================

function getAdminLoginHTML(): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<style>body{min-height:100vh;display:flex;align-items:center;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460)}.card{border:none;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.3)}</style>
</head><body><div class="container"><div class="row justify-content-center"><div class="col-md-4"><div class="card"><div class="card-body p-4">
<h4 class="text-center mb-4"><i class="bi bi-shield-lock"></i> Admin Login</h4>
<div id="error" class="alert alert-danger d-none"></div>
<form id="f"><div class="mb-3"><label class="form-label">Username</label><input type="text" class="form-control" name="username" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>
<button type="submit" class="btn btn-primary w-100">Sign In</button></form></div></div></div></div></div>
<script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;b.textContent='Signing in...';try{const r=await fetch('/admin/login',{method:'POST',body:new FormData(e.target)});const d=await r.json();if(d.ok)location.reload();else{document.getElementById('error').textContent=d.error||'Login failed';document.getElementById('error').classList.remove('d-none')}}finally{b.disabled=false;b.textContent='Sign In'}};</script></body></html>`;
}

function getAdminDashboardHTML(): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Panel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<style>body{background:#f8f9fa}.sb{background:#212529;min-height:100vh;padding-top:1rem}.sb .nav-link{color:#adb5bd;padding:.6rem 1rem;border-radius:6px;margin:2px 8px}.sb .nav-link:hover,.sb .nav-link.active{color:#fff;background:rgba(255,255,255,.1)}.sb .nav-link i{width:20px;margin-right:8px}.card{border:none;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.08)}.sc{transition:transform .2s}.sc:hover{transform:translateY(-2px)}.table th{font-weight:600;font-size:.85rem;text-transform:uppercase;color:#6c757d}#tc{position:fixed;top:20px;right:20px;z-index:9999}</style>
</head><body><div id="tc"></div><div class="d-flex">
<div class="sb d-flex flex-column" style="width:250px">
<div class="px-3 mb-3"><h5 class="text-white mb-0"><i class="bi bi-gear-fill"></i> Admin</h5><small class="text-muted">Google Drive Index</small></div>
<nav class="nav flex-column flex-grow-1">
<a class="nav-link active" href="#" data-tab="dashboard"><i class="bi bi-speedometer2"></i>Dashboard</a>
<a class="nav-link" href="#" data-tab="credentials"><i class="bi bi-person-badge"></i>Credentials</a>
<a class="nav-link" href="#" data-tab="drives"><i class="bi bi-hdd-stack"></i>Drives</a>
<a class="nav-link" href="#" data-tab="config"><i class="bi bi-sliders"></i>Configuration</a>
<a class="nav-link" href="#" data-tab="sa"><i class="bi bi-key"></i>Service Accounts</a>
<a class="nav-link" href="#" data-tab="google-login"><i class="bi bi-google"></i>Google Login</a>
<a class="nav-link" href="#" data-tab="security"><i class="bi bi-shield-check"></i>Security</a>
</nav>
<div class="px-3 pb-3 mt-auto">
<a href="/" class="btn btn-outline-light btn-sm w-100 mb-2" target="_blank"><i class="bi bi-box-arrow-up-right"></i> View Site</a>
<a href="/admin/logout" class="btn btn-outline-danger btn-sm w-100"><i class="bi bi-box-arrow-left"></i> Logout</a>
</div></div>
<div class="flex-grow-1 p-4" style="min-height:100vh" id="main"></div></div>

<!-- Drive Modal -->
<div class="modal fade" id="dm" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title" id="dmt">Add Drive</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><input type="hidden" id="dei">
<div class="mb-3"><label class="form-label">Drive Name</label><input type="text" class="form-control" id="dn" placeholder="My Shared Drive"></div>
<div class="mb-3"><label class="form-label">Drive / Folder ID</label><input type="text" class="form-control font-monospace" id="di" placeholder="0ABCD... or root">
<button class="btn btn-outline-info btn-sm mt-1" onclick="fetchRoot()"><i class="bi bi-arrow-repeat"></i> Fetch Root Info</button>
<small id="fetchResult" class="d-block mt-1 text-muted"></small></div>
<div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="dp"><label class="form-check-label" for="dp">Protect file links</label></div>
</div><div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="saveDrive()">Save</button></div>
</div></div></div>

<!-- Config Modal -->
<div class="modal fade" id="cm" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Config Key</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><div class="mb-3"><label class="form-label">Key</label><input type="text" class="form-control font-monospace" id="ck" placeholder="category.key_name"></div>
<div class="mb-3"><label class="form-label">Value</label><input type="text" class="form-control" id="cv"></div></div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addCfgKey()">Add</button></div>
</div></div></div>

<!-- SA Modal -->
<div class="modal fade" id="sm" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Service Account</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><textarea class="form-control font-monospace" id="sj" rows="10" placeholder="Paste service account JSON..."></textarea></div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addSA()">Add</button></div>
</div></div></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
let AD=[],AC=[],ASA=[];
const $=s=>document.getElementById(s),$$=s=>document.querySelectorAll(s);
const esc=s=>s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function toast(m,t='success'){const id='t'+Date.now();$('tc').insertAdjacentHTML('beforeend','<div id="'+id+'" class="toast show align-items-center text-bg-'+t+' border-0 mb-2" role="alert"><div class="d-flex"><div class="toast-body">'+m+'</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>');setTimeout(()=>{const e=$(id);if(e)e.remove()},3000)}

async function api(p,b){const o=b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{};const r=await fetch('/admin/api/'+p,o);const d=await r.json();if(d.error)throw new Error(d.error);return d}

// Known boolean/select config keys
const BOOL_KEYS=['auth.enable_login','auth.enable_signup','auth.search_all_drives','auth.enable_cors_file_down','auth.enable_password_file_verify','auth.direct_link_protection','auth.disable_anonymous_download','auth.enable_ip_lock','auth.single_session','ui.logo_image','ui.fixed_header','ui.fixed_footer','ui.hide_footer','ui.credit','ui.display_size','ui.display_time','ui.display_download','ui.disable_player','ui.disable_video_download','ui.allow_selecting_files','ui.second_domain_for_dl','ui.render_head_md','ui.render_readme_md','ui.show_logout_button'];
const SELECT_KEYS={'site.download_mode':['path','id'],'player.player':['videojs','plyr','dplayer','jwplayer'],'ui.theme':['cerulean','cosmo','cyborg','darkly','flatly','journal','litera','lumen','lux','materia','minty','morph','pulse','quartz','sandstone','simplex','sketchy','slate','solar','spacelab','superhero','united','vapor','yeti','zephyr']};

function sc(i,l,v,c){return '<div class="col-md-3"><div class="card sc border-start border-4 border-'+c+'"><div class="card-body py-3"><div class="d-flex align-items-center"><div class="flex-grow-1"><div class="text-muted small">'+l+'</div><div class="h4 mb-0">'+v+'</div></div><i class="bi '+i+' fs-2 text-'+c+'"></i></div></div></div></div>'}

// Tab navigation
document.querySelectorAll('[data-tab]').forEach(a=>{a.addEventListener('click',e=>{e.preventDefault();const t=a.dataset.tab;document.querySelectorAll('.sb .nav-link').forEach(n=>n.classList.remove('active'));a.classList.add('active');loadTab(t)})});

function loadTab(t){
  const m=$('main');
  m.innerHTML='<div class="text-center py-5"><div class="spinner-border"></div></div>';
  switch(t){
    case 'dashboard':return loadDash();
    case 'credentials':return loadCreds();
    case 'drives':return loadDrives();
    case 'config':return loadCfg();
    case 'sa':return loadSA();
    case 'google-login':return loadGL();
    case 'security':return loadSec();
  }
}

// ===== Dashboard =====
async function loadDash(){
  try{
    const[d,c,s]=await Promise.all([api('drives'),api('config'),api('service-accounts')]);
    AD=d.drives;AC=c.config;ASA=s.accounts;
    const gv=k=>(AC.find(x=>x.key===k)||{}).value||'';
    $('main').innerHTML='<h4 class="mb-4">Dashboard</h4><div class="row g-3 mb-4">'+
      sc('bi-hdd-stack','Drives',AD.length,'primary')+sc('bi-key','Service Accounts',ASA.length,'warning')+
      sc('bi-sliders','Config Keys',AC.length,'info')+sc('bi-shield-check','Login',gv('auth.enable_login')==='true'?'Enabled':'Disabled',gv('auth.enable_login')==='true'?'success':'secondary')+
      '</div><div class="card"><div class="card-header"><h6 class="mb-0">Overview</h6></div><div class="card-body">'+
      '<div class="row mb-2"><div class="col-md-6"><strong>Site Name:</strong> '+esc(gv('site.name')||'Google Drive Index')+'</div><div class="col-md-6"><strong>Download Mode:</strong> '+esc(gv('site.download_mode')||'path')+'</div></div>'+
      '<hr><h6>Drives</h6>'+(AD.length?'<ul class="list-group list-group-flush">'+AD.map(x=>'<li class="list-group-item d-flex justify-content-between"><span>'+esc(x.name)+'</span><code>'+esc(x.drive_id)+'</code></li>').join('')+'</ul>':'<p class="text-muted">No drives</p>')+
      '</div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}

// ===== Credentials =====
async function loadCreds(){
  try{
    const d=await api('credentials');const c=d.credentials;
    $('main').innerHTML='<h4 class="mb-4">OAuth Credentials</h4>'+
      '<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Google OAuth2</h6></div><div class="card-body">'+
      '<p class="text-muted small">Credentials are never displayed once saved. Enter new values to update.</p>'+
      '<div class="mb-3"><label class="form-label">Client ID '+(c['auth.client_id']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="text" class="form-control" id="cr-cid" placeholder="Enter client ID"></div>'+
      '<div class="mb-3"><label class="form-label">Client Secret '+(c['auth.client_secret']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="cr-cs" placeholder="Enter client secret"></div>'+
      '<div class="mb-3"><label class="form-label">Refresh Token '+(c['auth.refresh_token']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="cr-rt" placeholder="Enter refresh token"></div>'+
      '<button class="btn btn-primary" onclick="saveCreds()"><i class="bi bi-save"></i> Save Credentials</button>'+
      '</div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
async function saveCreds(){
  const b={};
  const cid=$('cr-cid').value.trim();if(cid)b.client_id=cid;
  const cs=$('cr-cs').value.trim();if(cs)b.client_secret=cs;
  const rt=$('cr-rt').value.trim();if(rt)b.refresh_token=rt;
  if(!Object.keys(b).length){toast('Enter at least one field','warning');return}
  try{await api('credentials/save',b);toast('Credentials saved!');loadCreds()}catch(e){toast(e.message,'danger')}
}

// ===== Drives =====
async function loadDrives(){
  try{
    const d=await api('drives');AD=d.drives;
    $('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0">Drives</h4>'+
      '<button class="btn btn-primary" onclick="showDM()"><i class="bi bi-plus-lg"></i> Add Drive</button></div>'+
      '<div class="card"><div class="card-body p-0"><table class="table table-hover mb-0"><thead><tr><th>#</th><th>Name</th><th>Drive ID</th><th>Protected</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+
      (AD.length?AD.map((x,i)=>'<tr><td>'+i+'</td><td><strong>'+esc(x.name)+'</strong></td><td><code class="small">'+esc(x.drive_id)+'</code></td>'+
        '<td>'+(x.protect_file_link?'<span class="badge bg-warning">Yes</span>':'<span class="badge bg-secondary">No</span>')+'</td>'+
        '<td>'+(x.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Disabled</span>')+'</td>'+
        '<td><button class="btn btn-sm btn-outline-primary me-1" onclick="editDr('+x.id+')"><i class="bi bi-pencil"></i></button>'+
        '<button class="btn btn-sm btn-outline-danger" onclick="delDr('+x.id+')"><i class="bi bi-trash"></i></button></td></tr>').join(''):
        '<tr><td colspan="6" class="text-center text-muted py-4">No drives. Click "Add Drive".</td></tr>')+
      '</tbody></table></div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
function showDM(){$('dmt').textContent='Add Drive';$('dei').value='';$('dn').value='';$('di').value='';$('dp').checked=false;$('fetchResult').textContent='';new bootstrap.Modal($('dm')).show()}
function editDr(id){const d=AD.find(x=>x.id===id);if(!d)return;$('dmt').textContent='Edit Drive';$('dei').value=d.id;$('dn').value=d.name;$('di').value=d.drive_id;$('dp').checked=!!d.protect_file_link;$('fetchResult').textContent='';new bootstrap.Modal($('dm')).show()}
async function saveDrive(){const eid=$('dei').value;const b={name:$('dn').value,drive_id:$('di').value,protect_file_link:$('dp').checked};try{if(eid)await api('drives/update',{...b,id:parseInt(eid),enabled:true});else await api('drives/add',b);bootstrap.Modal.getInstance($('dm')).hide();toast(eid?'Updated':'Added');loadDrives()}catch(e){toast(e.message,'danger')}}
async function delDr(id){if(!confirm('Delete this drive?'))return;try{await api('drives/delete',{id});toast('Deleted');loadDrives()}catch(e){toast(e.message,'danger')}}
async function fetchRoot(){const did=$('di').value.trim();if(!did){toast('Enter a drive ID first','warning');return}$('fetchResult').innerHTML='<span class="spinner-border spinner-border-sm"></span> Fetching...';try{const d=await api('drives/fetch-root',{drive_id:did});$('fetchResult').innerHTML='<span class="text-success"><i class="bi bi-check-circle"></i> '+esc(d.name)+' ('+esc(d.root_id)+')</span>';if(d.name&&!$('dn').value)$('dn').value=d.name}catch(e){$('fetchResult').innerHTML='<span class="text-danger"><i class="bi bi-x-circle"></i> '+esc(e.message)+'</span>'}}

// ===== Config =====
async function loadCfg(){
  try{
    const d=await api('config');AC=d.config;
    const grp={};AC.forEach(c=>{const cat=c.key.split('.')[0]||'other';if(!grp[cat])grp[cat]=[];grp[cat].push(c)});
    $('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0">Configuration</h4><div>'+
      '<button class="btn btn-outline-primary btn-sm" onclick="showCM()"><i class="bi bi-plus-lg"></i> Add Key</button>'+
      '<button class="btn btn-primary btn-sm ms-2" onclick="saveCfg()"><i class="bi bi-save"></i> Save All</button></div></div>'+
      Object.keys(grp).sort().map(cat=>'<div class="card mb-3"><div class="card-header d-flex justify-content-between"><h6 class="mb-0 text-capitalize">'+cat+'</h6><span class="badge bg-secondary">'+grp[cat].length+'</span></div>'+
        '<div class="card-body p-0"><table class="table table-sm mb-0"><tbody>'+grp[cat].map(c=>{
          const isBool=BOOL_KEYS.includes(c.key);
          const selOpts=SELECT_KEYS[c.key];
          let input;
          if(isBool)input='<select class="form-select form-select-sm ci" data-key="'+esc(c.key)+'"><option value="true"'+(c.value==='true'?' selected':'')+'>true</option><option value="false"'+(c.value!=='true'?' selected':'')+'>false</option></select>';
          else if(selOpts)input='<select class="form-select form-select-sm ci" data-key="'+esc(c.key)+'">'+selOpts.map(o=>'<option value="'+o+'"'+(c.value===o?' selected':'')+'>'+o+'</option>').join('')+'</select>';
          else input='<input type="text" class="form-control form-control-sm ci" data-key="'+esc(c.key)+'" value="'+esc(c.value)+'">';
          return '<tr><td style="width:35%"><code>'+esc(c.key)+'</code></td><td>'+input+'</td><td style="width:50px"><button class="btn btn-sm btn-outline-danger" onclick="delCfg(\''+esc(c.key)+'\')"><i class="bi bi-trash"></i></button></td></tr>'
        }).join('')+'</tbody></table></div></div>').join('')||'<div class="text-muted text-center py-4">No config keys.</div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
function showCM(){$('ck').value='';$('cv').value='';new bootstrap.Modal($('cm')).show()}
async function addCfgKey(){const k=$('ck').value.trim(),v=$('cv').value;if(!k){toast('Key required','warning');return}try{await api('config/set',{key:k,value:v});bootstrap.Modal.getInstance($('cm')).hide();toast('Added');loadCfg()}catch(e){toast(e.message,'danger')}}
async function delCfg(k){if(!confirm('Delete "'+k+'"?'))return;try{await api('config/delete',{key:k});toast('Deleted');loadCfg()}catch(e){toast(e.message,'danger')}}
async function saveCfg(){const items=[];document.querySelectorAll('.ci').forEach(el=>items.push({key:el.dataset.key,value:el.value}));try{await api('config/bulk',{items});toast('All saved!')}catch(e){toast(e.message,'danger')}}

// ===== Service Accounts =====
async function loadSA(){
  try{const d=await api('service-accounts');ASA=d.accounts;
    $('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0">Service Accounts</h4>'+
      '<button class="btn btn-primary" onclick="showSM()"><i class="bi bi-plus-lg"></i> Add</button></div>'+
      '<div class="card"><div class="card-body p-0"><table class="table table-hover mb-0"><thead><tr><th>#</th><th>Name</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+
      (ASA.length?ASA.map((s,i)=>'<tr><td>'+(i+1)+'</td><td>'+esc(s.name)+'</td><td>'+(s.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Disabled</span>')+'</td>'+
        '<td><button class="btn btn-sm btn-outline-danger" onclick="delSA('+s.id+')"><i class="bi bi-trash"></i></button></td></tr>').join(''):
        '<tr><td colspan="4" class="text-center text-muted py-4">No service accounts.</td></tr>')+
      '</tbody></table></div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
function showSM(){$('sj').value='';new bootstrap.Modal($('sm')).show()}
async function addSA(){const j=$('sj').value.trim();if(!j){toast('JSON required','warning');return}try{JSON.parse(j)}catch{toast('Invalid JSON','danger');return}try{await api('service-accounts/add',{json_data:j});bootstrap.Modal.getInstance($('sm')).hide();toast('Added');loadSA()}catch(e){toast(e.message,'danger')}}
async function delSA(id){if(!confirm('Delete?'))return;try{await api('service-accounts/delete',{id});toast('Deleted');loadSA()}catch(e){toast(e.message,'danger')}}

// ===== Google Login =====
async function loadGL(){
  try{const d=await api('google-login');
    $('main').innerHTML='<h4 class="mb-4">Google Login</h4><div class="card"><div class="card-header"><h6 class="mb-0">Login with Google</h6></div><div class="card-body">'+
      '<p class="text-muted small">Credentials are never displayed once saved.</p>'+
      '<div class="mb-3"><label class="form-label">Enable Google Login</label><select class="form-select" id="gl-en"><option value="true"'+(d['auth.enable_social_login']?' selected':'')+'>Enabled</option><option value="false"'+(!d['auth.enable_social_login']?' selected':'')+'>Disabled</option></select></div>'+
      '<div class="mb-3"><label class="form-label">Google Client ID '+(d['google_login.client_id']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="text" class="form-control" id="gl-cid" placeholder="Enter Google Client ID"></div>'+
      '<div class="mb-3"><label class="form-label">Google Client Secret '+(d['google_login.client_secret']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="gl-cs" placeholder="Enter Google Client Secret"></div>'+
      '<button class="btn btn-primary" onclick="saveGL()"><i class="bi bi-save"></i> Save</button></div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
async function saveGL(){const b={enabled:$('gl-en').value==='true'};const cid=$('gl-cid').value.trim();if(cid)b.client_id=cid;const cs=$('gl-cs').value.trim();if(cs)b.client_secret=cs;try{await api('google-login/save',b);toast('Saved!');loadGL()}catch(e){toast(e.message,'danger')}}

// ===== Security =====
async function loadSec(){
  try{const d=await api('security');
    $('main').innerHTML='<h4 class="mb-4">Security</h4>'+
      '<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Admin Credentials</h6></div><div class="card-body">'+
      '<div class="row g-3"><div class="col-md-6"><label class="form-label">Username</label><input type="text" class="form-control" id="su" value="'+esc(d['admin.username'])+'"></div>'+
      '<div class="col-md-6"><label class="form-label">New Password '+(d['admin.password_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="sp" placeholder="Enter new password"></div></div>'+
      '<button class="btn btn-primary mt-3" onclick="saveSec()"><i class="bi bi-save"></i> Save</button></div></div>'+
      '<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Blocked Regions / ASNs</h6></div><div class="card-body">'+
      '<div class="mb-3"><label class="form-label">Blocked Regions (comma-separated country codes)</label><input type="text" class="form-control" id="sr" value="'+esc(d['security.blocked_regions'])+'" placeholder="e.g. CN, RU"></div>'+
      '<div class="mb-3"><label class="form-label">Blocked ASNs (comma-separated)</label><input type="text" class="form-control" id="sa" value="'+esc(d['security.blocked_asn'])+'" placeholder="e.g. 12345, 67890"></div>'+
      '<button class="btn btn-primary" onclick="saveBlk()"><i class="bi bi-save"></i> Save</button></div></div>'+
      '<div class="card"><div class="card-header"><h6 class="mb-0">Crypto Keys</h6></div><div class="card-body">'+
      '<div class="mb-3"><label class="form-label">Encryption Key '+(d['security.crypto_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><br>'+
      '<button class="btn btn-outline-warning btn-sm" onclick="regenKey(\'crypto\')"><i class="bi bi-arrow-repeat"></i> Regenerate Crypto Key</button></div>'+
      '<div class="mb-3"><label class="form-label">HMAC Key '+(d['security.hmac_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><br>'+
      '<button class="btn btn-outline-warning btn-sm" onclick="regenKey(\'hmac\')"><i class="bi bi-arrow-repeat"></i> Regenerate HMAC Key</button></div>'+
      '</div></div>';
  }catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}
}
async function saveSec(){const b={};const u=$('su').value.trim();if(u)b.admin_username=u;const p=$('sp').value;if(p)b.admin_password=p;if(!Object.keys(b).length){toast('Nothing to save','warning');return}try{await api('security/save',b);toast('Saved!');loadSec()}catch(e){toast(e.message,'danger')}}
async function saveBlk(){try{await api('security/save',{blocked_regions:$('sr').value,blocked_asn:$('sa').value});toast('Saved!')}catch(e){toast(e.message,'danger')}}
async function regenKey(t){if(!confirm('Regenerate '+t+' key? Existing encrypted data will become invalid.'))return;try{await api('security/regenerate-key',{type:t});toast(t+' key regenerated!');loadSec()}catch(e){toast(e.message,'danger')}}

// Init
loadDash();
</script></body></html>`;
}
