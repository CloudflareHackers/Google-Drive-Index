/**
 * Admin Panel Module - Full CRUD for D1 configuration
 * @version 3.3.0
 * Features: Multiple credentials, service accounts, drive auth selection
 */

import { config, adminConfig } from '../config';
import { encryptString, decryptString, generateIntegrity, verifyIntegrity } from '../utils/crypto';
import { parseCookies, buildCookie, jsonResponse, htmlResponse } from '../utils/helpers';
import { getAdminLoginHTML, getAdminDashboardHTML } from './dashboard-html';
import type { Env } from '../types';

const ADMIN_SESSION_NAME = 'admin_session';

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
    const [, expiryStr] = data.split('|');
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
// Ensure tables exist (auto-migration)
// ============================================================================
async function ensureTables(env: Env): Promise<void> {
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS oauth_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      refresh_token TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();
  } catch { /* already exists */ }

  // Add auth_type and credential_id columns to drives if not present
  try { await env.DB.prepare(`ALTER TABLE drives ADD COLUMN auth_type TEXT DEFAULT 'oauth'`).run(); } catch { /* exists */ }
  try { await env.DB.prepare(`ALTER TABLE drives ADD COLUMN credential_id INTEGER DEFAULT NULL`).run(); } catch { /* exists */ }
}

// ============================================================================
// OAuth Credentials API (stored individually, never exposed)
// ============================================================================

async function apiListOAuthCreds(env: Env): Promise<Response> {
  await ensureTables(env);
  const result = await env.DB.prepare(
    'SELECT id, name, created_at FROM oauth_credentials ORDER BY id'
  ).all();
  return jsonResponse({ credentials: result.results || [] });
}

async function apiAddOAuthCred(body: any, env: Env): Promise<Response> {
  await ensureTables(env);
  if (!body.name || !body.client_id || !body.client_secret || !body.refresh_token) {
    return jsonResponse({ error: 'name, client_id, client_secret, and refresh_token are all required' }, 400);
  }
  await env.DB.prepare(
    'INSERT INTO oauth_credentials (name, client_id, client_secret, refresh_token) VALUES (?, ?, ?, ?)'
  ).bind(body.name, body.client_id, body.client_secret, body.refresh_token).run();
  return jsonResponse({ ok: true });
}

async function apiDeleteOAuthCred(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  // Check if any drives reference this credential
  const usage = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM drives WHERE auth_type='oauth' AND credential_id=?"
  ).bind(body.id).first<{cnt:number}>();
  if (usage && usage.cnt > 0) {
    return jsonResponse({ error: 'Cannot delete: ' + usage.cnt + ' drive(s) use this credential. Update those drives first.' }, 400);
  }
  await env.DB.prepare('DELETE FROM oauth_credentials WHERE id=?').bind(body.id).run();
  return jsonResponse({ ok: true });
}

// ============================================================================
// Drives API (updated with auth_type & credential_id)
// ============================================================================

async function apiGetDrives(env: Env): Promise<Response> {
  await ensureTables(env);
  const result = await env.DB.prepare(
    `SELECT d.*, 
      CASE WHEN d.auth_type='oauth' AND d.credential_id IS NOT NULL 
        THEN (SELECT name FROM oauth_credentials WHERE id=d.credential_id) 
        ELSE NULL END as credential_name,
      CASE WHEN d.auth_type='service_account' AND d.credential_id IS NOT NULL
        THEN (SELECT name FROM service_accounts WHERE id=d.credential_id)
        ELSE NULL END as sa_name
    FROM drives d ORDER BY d.order_index`
  ).all();
  return jsonResponse({ drives: result.results || [] });
}

async function resolveRootId(driveId: string, credentialId: number | null, env: Env): Promise<string> {
  if (driveId !== 'root') return driveId;
  try {
    let clientId: string | undefined, clientSecret: string | undefined, refreshToken: string | undefined;
    if (credentialId) {
      const cred = await env.DB.prepare('SELECT client_id, client_secret, refresh_token FROM oauth_credentials WHERE id=?')
        .bind(credentialId).first<{client_id:string;client_secret:string;refresh_token:string}>();
      if (cred) { clientId = cred.client_id; clientSecret = cred.client_secret; refreshToken = cred.refresh_token; }
    }
    if (!clientId) {
      clientId = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_id'").first<{value:string}>())?.value;
      clientSecret = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_secret'").first<{value:string}>())?.value;
      refreshToken = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.refresh_token'").first<{value:string}>())?.value;
    }
    if (!clientId || !clientSecret || !refreshToken) return driveId;
    const tokenRes = await fetch('https://www.googleapis.com/oauth2/v4/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${encodeURIComponent(refreshToken)}&grant_type=refresh_token`
    });
    const tokenData = await tokenRes.json() as any;
    if (!tokenData.access_token) return driveId;
    const res = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const data = await res.json() as any;
    return data.id || driveId;
  } catch { return driveId; }
}

async function apiAddDrive(body: any, env: Env): Promise<Response> {
  await ensureTables(env);
  if (!body.drive_id || !body.name) return jsonResponse({ error: 'drive_id and name required' }, 400);
  const authType = body.auth_type || 'oauth';
  const credentialId = body.credential_id || null;
  // Auto-resolve "root" to actual root folder ID
  const resolvedDriveId = await resolveRootId(body.drive_id, credentialId, env);
  const maxOrder = await env.DB.prepare('SELECT MAX(order_index) as mx FROM drives').first<{mx:number}>();
  await env.DB.prepare(
    'INSERT INTO drives (drive_id, name, order_index, protect_file_link, enabled, auth_type, credential_id) VALUES (?, ?, ?, ?, 1, ?, ?)'
  ).bind(resolvedDriveId, body.name, (maxOrder?.mx ?? -1) + 1, body.protect_file_link ? 1 : 0, authType, credentialId).run();
  return jsonResponse({ ok: true, resolved_id: resolvedDriveId !== body.drive_id ? resolvedDriveId : undefined });
}

async function apiUpdateDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  const credentialId = body.credential_id || null;
  // Auto-resolve "root" to actual root folder ID
  const resolvedDriveId = await resolveRootId(body.drive_id, credentialId, env);
  await env.DB.prepare(
    'UPDATE drives SET name=?, drive_id=?, protect_file_link=?, enabled=?, auth_type=?, credential_id=? WHERE id=?'
  ).bind(
    body.name, resolvedDriveId, body.protect_file_link ? 1 : 0, body.enabled ? 1 : 0,
    body.auth_type || 'oauth', credentialId, body.id
  ).run();
  return jsonResponse({ ok: true, resolved_id: resolvedDriveId !== body.drive_id ? resolvedDriveId : undefined });
}

async function apiDeleteDrive(body: any, env: Env): Promise<Response> {
  if (!body.id) return jsonResponse({ error: 'id required' }, 400);
  await env.DB.prepare('DELETE FROM drives WHERE id=?').bind(body.id).run();
  return jsonResponse({ ok: true });
}

// ============================================================================
// Config API
// ============================================================================

const HIDDEN_FROM_CONFIG = ['admin.password','admin.username','auth.client_id','auth.client_secret','auth.refresh_token','security.crypto_key','security.hmac_key','google_login.client_id','google_login.client_secret','security.blocked_regions','security.blocked_asn','setup.completed'];

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

// ============================================================================
// Google Login API
// ============================================================================

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

// ============================================================================
// Security API
// ============================================================================

async function apiGetSecurityStatus(env: Env): Promise<Response> {
  const results: Record<string,any> = {};
  for (const k of ['admin.username','security.blocked_regions','security.blocked_asn']) {
    const r = await env.DB.prepare('SELECT value FROM config WHERE key=?').bind(k).first<{value:string}>();
    results[k] = r?.value || '';
  }
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

// ============================================================================
// Fetch Root ID API
// ============================================================================

async function getAccessTokenForAdmin(credentialId: number | null, authType: string | undefined, env: Env): Promise<{access_token: string} | {error: string}> {
  // Service Account auth - use JWT
  if (authType === 'service_account' && credentialId) {
    try {
      const sa = await env.DB.prepare('SELECT json_data FROM service_accounts WHERE id=?').bind(credentialId).first<{json_data:string}>();
      if (!sa?.json_data) return { error: 'Service account not found' };
      const saJson = JSON.parse(sa.json_data);
      const { generateGCPToken } = await import('../utils/crypto');
      const jwt = await generateGCPToken(saJson);
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
      });
      const tokenData = await tokenRes.json() as any;
      if (!tokenData.access_token) return { error: 'Service account auth failed. Check the JSON key.' };
      return { access_token: tokenData.access_token };
    } catch (e) { return { error: 'SA error: ' + (e as Error).message }; }
  }

  // OAuth credential auth
  let clientId: string | undefined, clientSecret: string | undefined, refreshToken: string | undefined;
  if (credentialId) {
    const cred = await env.DB.prepare('SELECT client_id, client_secret, refresh_token FROM oauth_credentials WHERE id=?')
      .bind(credentialId).first<{client_id:string;client_secret:string;refresh_token:string}>();
    if (cred) { clientId = cred.client_id; clientSecret = cred.client_secret; refreshToken = cred.refresh_token; }
  }
  if (!clientId || !clientSecret || !refreshToken) return { error: 'No credentials found. Select a credential first.' };
  const tokenRes = await fetch('https://www.googleapis.com/oauth2/v4/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${encodeURIComponent(refreshToken)}&grant_type=refresh_token`
  });
  const tokenData = await tokenRes.json() as any;
  if (!tokenData.access_token) return { error: 'Failed to get access token. Check credentials.' };
  return { access_token: tokenData.access_token };
}

async function apiListSharedDrives(body: any, env: Env): Promise<Response> {
  try {
    if (!body.credential_id) return jsonResponse({ error: 'Please select a credential first' }, 400);
    const token = await getAccessTokenForAdmin(body.credential_id, body.auth_type, env);
    if ('error' in token) return jsonResponse({ error: token.error }, 400);
    const res = await fetch('https://www.googleapis.com/drive/v3/drives?pageSize=100&fields=drives(id,name)', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    const data = await res.json() as any;
    if (data.error) return jsonResponse({ error: data.error.message || 'API error' }, 400);
    // Also get the user's root drive
    const rootRes = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id,name', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    const rootData = await rootRes.json() as any;
    const drives = [{ id: rootData.id, name: rootData.name || 'My Drive', type: 'personal' }];
    if (data.drives) {
      for (const d of data.drives) { drives.push({ id: d.id, name: d.name, type: 'shared' }); }
    }
    return jsonResponse({ drives });
  } catch (e) { return jsonResponse({ error: (e as Error).message }, 500); }
}

async function apiFetchRootId(body: any, env: Env): Promise<Response> {
  try {
    if (!body.credential_id) return jsonResponse({ error: 'Please select a credential first' }, 400);
    const token = await getAccessTokenForAdmin(body.credential_id, body.auth_type, env);
    if ('error' in token) return jsonResponse({ error: token.error }, 400);
    const driveId = body.drive_id;
    if (!driveId) return jsonResponse({ error: 'drive_id required' }, 400);
    if (driveId === 'root') {
      const res = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id,name', { headers: { Authorization: `Bearer ${token.access_token}` } });
      const data = await res.json() as any;
      return jsonResponse({ root_id: data.id, name: data.name || 'My Drive' });
    }
    // Try as shared drive first
    const sdRes = await fetch(`https://www.googleapis.com/drive/v3/drives/${driveId}?fields=id,name`, { headers: { Authorization: `Bearer ${token.access_token}` } });
    const sdData = await sdRes.json() as any;
    if (sdData.name) {
      return jsonResponse({ root_id: sdData.id, name: sdData.name, type: 'shared_drive' });
    }
    // Fall back to file/folder lookup
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${driveId}?fields=id,name,mimeType&supportsAllDrives=true`, { headers: { Authorization: `Bearer ${token.access_token}` } });
    const data = await res.json() as any;
    if (data.error) return jsonResponse({ error: data.error.message || 'Drive API error' }, 400);
    return jsonResponse({ root_id: data.id, name: data.name, mimeType: data.mimeType });
  } catch (e) { return jsonResponse({ error: (e as Error).message }, 500); }
}

// ============================================================================
// Service Accounts API
// ============================================================================

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
  // Check if any drives reference this SA
  const usage = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM drives WHERE auth_type='service_account' AND credential_id=?"
  ).bind(body.id).first<{cnt:number}>();
  if (usage && usage.cnt > 0) {
    return jsonResponse({ error: 'Cannot delete: ' + usage.cnt + ' drive(s) use this service account. Update those drives first.' }, 400);
  }
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
    return htmlResponse(authenticated ? getAdminDashboardHTML(url.origin) : getAdminLoginHTML());
  }
  if (path === '/admin/login' && request.method === 'POST') return handleAdminLogin(request, env);
  if (path === '/admin/logout') return handleAdminLogout();

  if (!authenticated) return jsonResponse({ error: 'Unauthorized' }, 401);
  if (!env?.DB) return jsonResponse({ error: 'D1 not configured' }, 500);

  if (request.method === 'GET') {
    switch (path) {
      case '/admin/api/drives': return apiGetDrives(env);
      case '/admin/api/config': return apiGetConfig(env);
      case '/admin/api/oauth-credentials': return apiListOAuthCreds(env);
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
      case '/admin/api/drives/list-shared': return apiListSharedDrives(body, env);
      case '/admin/api/config/set': return apiSetConfig(body, env);
      case '/admin/api/config/delete': return apiDeleteConfig(body, env);
      case '/admin/api/config/bulk': return apiBulkSetConfig(body, env);
      case '/admin/api/oauth-credentials/add': return apiAddOAuthCred(body, env);
      case '/admin/api/oauth-credentials/delete': return apiDeleteOAuthCred(body, env);
      case '/admin/api/google-login/save': return apiSaveGoogleLogin(body, env);
      case '/admin/api/security/save': return apiSaveSecurity(body, env);
      case '/admin/api/security/regenerate-key': return apiRegenerateKey(body, env);
      case '/admin/api/service-accounts/add': return apiAddServiceAccount(body, env);
      case '/admin/api/service-accounts/delete': return apiDeleteServiceAccount(body, env);
    }
  }
  return jsonResponse({ error: 'Not found' }, 404);
}