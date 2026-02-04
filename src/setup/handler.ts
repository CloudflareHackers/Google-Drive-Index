/**
 * Setup Wizard Handler
 * All configuration stored in D1 database
 */

import { getSetupWizardHTML, getSetupLoginHTML } from './templates';
import { htmlResponse, jsonResponse, parseCookies, buildCookie } from '../utils/helpers';
import type { Env } from '../types';

const SETUP_COOKIE = 'setup_auth';
const SETUP_SESSION_DURATION = 3600000; // 1 hour

/**
 * Check if setup is required (no config in D1)
 */
export async function isSetupRequired(env: Env): Promise<boolean> {
  try {
    const result = await env.DB.prepare(
      'SELECT value FROM config WHERE key = ? LIMIT 1'
    ).bind('setup.completed').first<{ value: string }>();
    return !result || result.value !== 'true';
  } catch {
    // Table doesn't exist yet = setup required
    return true;
  }
}

/**
 * Verify setup session cookie
 */
function verifySetupSession(request: Request, env: Env): boolean {
  const cookies = parseCookies(request.headers.get('cookie'));
  const token = cookies[SETUP_COOKIE];
  if (!token) return false;
  
  try {
    const [password, expiry] = atob(token).split('|');
    if (parseInt(expiry) < Date.now()) return false;
    return password === env.SETUP_PASSWORD;
  } catch {
    return false;
  }
}

/**
 * Main setup handler
 */
export async function handleSetup(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // Check if D1 is configured
  if (!env.DB) {
    return htmlResponse(`
      <h1>D1 Database Not Configured</h1>
      <p>Please run these commands:</p>
      <pre>wrangler d1 create google-drive-index-db</pre>
      <p>Then update wrangler.toml with the database_id and redeploy.</p>
    `, 500);
  }

  // Setup login page
  if (path === '/setup' || path === '/setup/') {
    const authenticated = verifySetupSession(request, env);
    if (!authenticated) {
      return htmlResponse(getSetupLoginHTML());
    }
    const step = parseInt(url.searchParams.get('step') || '1');
    return htmlResponse(getSetupWizardHTML(step));
  }

  // Setup login POST
  if (path === '/setup/login' && request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password') as string;
    
    if (password !== env.SETUP_PASSWORD) {
      return htmlResponse(getSetupLoginHTML('Invalid setup password'), 401);
    }
    
    const expiry = Date.now() + SETUP_SESSION_DURATION;
    const token = btoa(`${password}|${expiry}`);
    
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/setup?step=1',
        'Set-Cookie': buildCookie(SETUP_COOKIE, token, {
          path: '/setup',
          httpOnly: true,
          secure: true,
          sameSite: 'Strict',
          maxAge: SETUP_SESSION_DURATION / 1000
        })
      }
    });
  }

  // All other setup routes require authentication
  if (!verifySetupSession(request, env)) {
    return new Response(null, { status: 302, headers: { 'Location': '/setup' } });
  }

  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  const body = await request.json() as any;

  switch (path) {
    case '/setup/init-db':
      return handleInitDB(env);
    case '/setup/save-credentials':
      return handleSaveCredentials(body, env);
    case '/setup/save-drives':
      return handleSaveDrives(body, env);
    case '/setup/save-settings':
      return handleSaveSettings(body, env);
    case '/setup/complete':
      return handleComplete(env);
    default:
      return jsonResponse({ error: 'Not found' }, 404);
  }
}

/**
 * Initialize D1 database tables
 */
async function handleInitDB(env: Env): Promise<Response> {
  try {
    await env.DB.exec(`
      -- Config table (stores all settings)
      CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      -- Drives table
      CREATE TABLE IF NOT EXISTS drives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        drive_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        order_index INTEGER DEFAULT 0,
        protect_file_link INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1
      );

      -- Service accounts table
      CREATE TABLE IF NOT EXISTS service_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        json_data TEXT NOT NULL,
        enabled INTEGER DEFAULT 1
      );

      -- Users table (for login system)
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        enabled INTEGER DEFAULT 1
      );

      -- Sessions table
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);

    return jsonResponse({ success: true });
  } catch (error) {
    return jsonResponse({ success: false, error: (error as Error).message }, 500);
  }
}

/**
 * Save Google credentials to D1
 */
async function handleSaveCredentials(body: any, env: Env): Promise<Response> {
  try {
    const configs = [
      ['auth.client_id', body.client_id || ''],
      ['auth.client_secret', body.client_secret || ''],
      ['auth.refresh_token', body.refresh_token || ''],
    ];

    for (const [key, value] of configs) {
      await env.DB.prepare(
        'INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))'
      ).bind(key, value).run();
    }

    // Handle service account if provided
    if (body.service_account_json) {
      try {
        const sa = JSON.parse(body.service_account_json);
        await env.DB.prepare(
          'INSERT INTO service_accounts (name, json_data, enabled) VALUES (?, ?, 1)'
        ).bind(sa.client_email || 'Service Account', body.service_account_json).run();
      } catch (e) {
        return jsonResponse({ success: false, error: 'Invalid service account JSON' }, 400);
      }
    }

    return jsonResponse({ success: true });
  } catch (error) {
    return jsonResponse({ success: false, error: (error as Error).message }, 500);
  }
}

/**
 * Save drives to D1
 */
async function handleSaveDrives(body: any, env: Env): Promise<Response> {
  try {
    // Clear existing drives
    await env.DB.prepare('DELETE FROM drives').run();

    // Insert new drives
    for (let i = 0; i < body.drives.length; i++) {
      const drive = body.drives[i];
      if (drive.id) {
        await env.DB.prepare(
          'INSERT INTO drives (drive_id, name, order_index, protect_file_link, enabled) VALUES (?, ?, ?, ?, 1)'
        ).bind(drive.id, drive.name || `Drive ${i + 1}`, i, drive.protect ? 1 : 0).run();
      }
    }

    return jsonResponse({ success: true });
  } catch (error) {
    return jsonResponse({ success: false, error: (error as Error).message }, 500);
  }
}

/**
 * Save general settings to D1
 */
async function handleSaveSettings(body: any, env: Env): Promise<Response> {
  try {
    const settings: [string, string][] = [
      ['site.name', body.site_name || 'Google Drive Index'],
      ['site.download_mode', body.download_mode || 'path'],
      ['auth.enable_login', body.enable_login ? 'true' : 'false'],
      ['auth.enable_signup', body.enable_signup ? 'true' : 'false'],
      ['auth.redirect_domain', body.redirect_domain || ''],
      ['security.blocked_regions', body.blocked_regions || ''],
      ['security.blocked_asn', body.blocked_asn || ''],
      ['admin.username', body.admin_username || 'admin'],
      ['admin.password', body.admin_password || ''],
    ];

    for (const [key, value] of settings) {
      await env.DB.prepare(
        'INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))'
      ).bind(key, value).run();
    }

    return jsonResponse({ success: true });
  } catch (error) {
    return jsonResponse({ success: false, error: (error as Error).message }, 500);
  }
}

/**
 * Mark setup as complete
 */
async function handleComplete(env: Env): Promise<Response> {
  try {
    await env.DB.prepare(
      'INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime("now"))'
    ).bind('setup.completed', 'true').run();

    // Generate crypto keys if not set
    const cryptoKey = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    const hmacKey = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');

    await env.DB.prepare(
      'INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)'
    ).bind('security.crypto_key', cryptoKey).run();

    await env.DB.prepare(
      'INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)'
    ).bind('security.hmac_key', hmacKey).run();

    return jsonResponse({ success: true, redirect: '/' });
  } catch (error) {
    return jsonResponse({ success: false, error: (error as Error).message }, 500);
  }
}
