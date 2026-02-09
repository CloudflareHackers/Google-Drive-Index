/**
 * Admin Panel Module - Full CRUD for D1 configuration
 * @version 3.2.0
 * Features: Collapsible sidebar, global credentials, redirect URI, download method toggle
 */

import { config, adminConfig } from '../config';
import { encryptString, decryptString, generateIntegrity, verifyIntegrity } from '../utils/crypto';
import { parseCookies, buildCookie, jsonResponse, htmlResponse } from '../utils/helpers';
import { getAdminLoginHTML, getAdminDashboardHTML } from './dashboard-html';
import { getGoogleLoginScript, getSecurityScript } from './dashboard-scripts';
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

async function apiFetchRootId(body: any, env: Env): Promise<Response> {
  try {
    const clientId = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_id'").first<{value:string}>())?.value;
    const clientSecret = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.client_secret'").first<{value:string}>())?.value;
    const refreshToken = (await env.DB.prepare("SELECT value FROM config WHERE key='auth.refresh_token'").first<{value:string}>())?.value;
    if (!clientId || !clientSecret || !refreshToken) return jsonResponse({ error: 'OAuth credentials not configured' }, 400);
    const tokenRes = await fetch('https://www.googleapis.com/oauth2/v4/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${encodeURIComponent(refreshToken)}&grant_type=refresh_token`
    });
    const tokenData = await tokenRes.json() as any;
    if (!tokenData.access_token) return jsonResponse({ error: 'Failed to get access token' }, 500);
    const driveId = body.drive_id;
    if (!driveId) return jsonResponse({ error: 'drive_id required' }, 400);
    if (driveId === 'root') {
      const res = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id,name', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
      const data = await res.json() as any;
      return jsonResponse({ root_id: data.id, name: data.name || 'My Drive' });
    }
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${driveId}?fields=id,name,mimeType&supportsAllDrives=true`, { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const data = await res.json() as any;
    if (data.error) return jsonResponse({ error: data.error.message || 'Drive API error' }, 400);
    return jsonResponse({ root_id: data.id, name: data.name, mimeType: data.mimeType });
  } catch (e) { return jsonResponse({ error: (e as Error).message }, 500); }
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