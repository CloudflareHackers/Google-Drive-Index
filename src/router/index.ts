/**
 * Main Router & Request Handlers
 * @version 3.0.0
 */

import { config } from '../config';
import { initDrives, getDrive, getAllDrives, GoogleDrive } from '../services/drive';
import { validateSession, handleLogin, handleSignup, handleLogout, requiresAuth } from '../services/auth';
import { encryptString, decryptString, generateDownloadLink, verifyDownloadLink } from '../utils/crypto';
import { jsonResponse, htmlResponse, redirectResponse } from '../utils/helpers';
import { getMainHTML, getHomepageHTML, getLoginHTML, getErrorHTML, getBlockedHTML, getGlobalSearchHTML } from '../templates';
import { handleAdminRequest } from '../admin';
import { handleSetup, isSetupRequired } from '../setup';
import type { Env, DriveFile, ListRequestBody, SearchRequestBody } from '../types';

// Import static assets directly - served from worker bundle (no CDN)
import APP_JS_CONTENT from '../app.txt';
import FAVICON_DATA from '../../images/favicon.ico';
import LOGO_SVG from '../../images/logo.svg';
import POSTER_DATA from '../../images/poster.jpg';
import MUSIC_DATA from '../../images/music.jpg';

/**
 * Serve app.js from bundled content
 */
function serveAppJs(): Response {
  return new Response(APP_JS_CONTENT, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * Serve favicon from bundled content
 */
function serveFavicon(): Response {
  return new Response(FAVICON_DATA, {
    headers: {
      'Content-Type': 'image/x-icon',
      'Cache-Control': 'public, max-age=604800'
    }
  });
}

/**
 * Serve logo from bundled content
 */
function serveLogo(): Response {
  return new Response(LOGO_SVG, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=604800'
    }
  });
}

/**
 * Serve poster image from bundled content
 */
function servePoster(): Response {
  return new Response(POSTER_DATA, {
    headers: {
      'Content-Type': 'image/jpeg',
      'Cache-Control': 'public, max-age=604800'
    }
  });
}

/**
 * Serve music poster image from bundled content
 */
function serveMusic(): Response {
  return new Response(MUSIC_DATA, {
    headers: {
      'Content-Type': 'image/jpeg',
      'Cache-Control': 'public, max-age=604800'
    }
  });
}

/**
 * Load configuration from D1 database into runtime config
 */
async function loadConfigFromD1(env: Env): Promise<void> {
  try {
    // Load all config values
    const configs = await env.DB.prepare('SELECT key, value FROM config').all<{ key: string; value: string }>();
    
    for (const row of configs.results || []) {
      const { key, value } = row;
      
      switch (key) {
        case 'auth.client_id': config.auth.client_id = value; break;
        case 'auth.client_secret': config.auth.client_secret = value; break;
        case 'auth.refresh_token': config.auth.refresh_token = value; break;
        case 'site.name': config.auth.siteName = value; break;
        case 'site.download_mode': config.download_mode = value as 'path' | 'id'; break;
        case 'auth.enable_login': config.auth.enable_login = value === 'true'; break;
        case 'auth.enable_signup': config.auth.enable_signup = value === 'true'; break;
        case 'auth.redirect_domain': config.auth.redirect_domain = value; break;
        case 'security.blocked_regions': 
          config.blocked_region = value ? value.split(',').map(s => s.trim().toUpperCase()) : [];
          break;
        case 'security.blocked_asn':
          config.blocked_asn = value ? value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : [];
          break;
        case 'security.crypto_key': (config as any).crypto_base_key = value; break;
        case 'security.hmac_key': (config as any).hmac_base_key = value; break;
        case 'security.file_link_expiry': config.auth.file_link_expiry = parseInt(value) || 7; break;
        case 'auth.search_all_drives': config.auth.search_all_drives = value === 'true'; break;
      }
    }

    // Load drives with credentials via JOINs (single query, no N+1)
    const drives = await env.DB.prepare(`
      SELECT d.drive_id, d.name, d.protect_file_link, d.auth_type, d.credential_id,
        oc.client_id AS oc_client_id, oc.client_secret AS oc_client_secret, oc.refresh_token AS oc_refresh_token,
        sa.json_data AS sa_json_data
      FROM drives d
      LEFT JOIN oauth_credentials oc ON d.auth_type='oauth' AND d.credential_id=oc.id
      LEFT JOIN service_accounts sa ON d.auth_type='service_account' AND d.credential_id=sa.id
      WHERE d.enabled = 1
      ORDER BY d.order_index
    `).all<{
      drive_id: string; name: string; protect_file_link: number;
      auth_type: string; credential_id: number | null;
      oc_client_id: string | null; oc_client_secret: string | null; oc_refresh_token: string | null;
      sa_json_data: string | null;
    }>();
    
    if (drives.results) {
      config.auth.roots = drives.results.map(d => {
        const root: any = { id: d.drive_id, name: d.name, protect_file_link: d.protect_file_link === 1 };
        if (d.auth_type === 'service_account' && d.sa_json_data) {
          try {
            root._auth_type = 'service_account';
            root._sa_json = JSON.parse(d.sa_json_data);
          } catch {}
        } else if (d.auth_type === 'oauth' && d.oc_client_id) {
          root._auth_type = 'oauth';
          root._client_id = d.oc_client_id;
          root._client_secret = d.oc_client_secret;
          root._refresh_token = d.oc_refresh_token;
        }
        return root;
      });
    }

    // Load service accounts
    const serviceAccounts = await env.DB.prepare(
      'SELECT json_data FROM service_accounts WHERE enabled = 1'
    ).all<{ json_data: string }>();
    
    if (serviceAccounts.results && serviceAccounts.results.length > 0) {
      config.serviceaccounts = serviceAccounts.results.map(sa => JSON.parse(sa.json_data));
      config.auth.service_account = true;
      config.auth.service_account_json = config.serviceaccounts[0];
    }
  } catch (error) {
    console.error('Error loading config from D1:', error);
  }
}

/**
 * Main request handler
 */
export async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    const path = url.pathname;
    const userIp = request.headers.get('CF-Connecting-IP') || '';

    // Check if setup is required (config not in D1 yet)
    const setupRequired = await isSetupRequired(env);
    
    if (setupRequired && !path.startsWith('/setup')) {
      return redirectResponse('/setup');
    }

    // Setup wizard
    if (path.startsWith('/setup')) {
      return handleSetup(request, env);
    }

    // Serve static assets directly from worker bundle (no config needed)
    if (path === '/app.js') {
      return serveAppJs();
    }
    if (path === '/favicon.ico') {
      return serveFavicon();
    }
    if (path === '/logo.svg') {
      return serveLogo();
    }
    if (path === '/poster.jpg') {
      return servePoster();
    }
    if (path === '/music.jpg') {
      return serveMusic();
    }

    // Load config from D1 and apply to runtime config
    await loadConfigFromD1(env);

    // Check blocked regions/ASNs
    const cf = (request as any).cf;
    if (cf) {
      const region = cf.country as string;
      const asn = cf.asn as number;
      
      if (config.blocked_region.includes(region?.toUpperCase())) {
        return htmlResponse(getBlockedHTML(), 403);
      }
      if (config.blocked_asn.includes(asn)) {
        return htmlResponse(getBlockedHTML(), 403);
      }
    }

    // Admin panel
    const adminResponse = await handleAdminRequest(request, env);
    if (adminResponse) return adminResponse;

    // Static routes
    if (path === '/logout') return handleLogout();
    
    if (path === '/login') {
      if (request.method === 'POST') return handleLogin(request, env);
      return htmlResponse(getLoginHTML());
    }

    if (path === '/signup' && config.auth.enable_signup) {
      if (request.method === 'POST') return handleSignup(request, env);
      return htmlResponse(getLoginHTML()); // Use same template with signup mode
    }

    // Authentication check
    if (requiresAuth(path)) {
      const auth = await validateSession(request, env);
      if (!auth.authenticated) {
        return htmlResponse(getLoginHTML(), 401);
      }
    }

    // Initialize drives
    await initDrives();

    // Homepage
    if (path === '/') {
      return htmlResponse(getHomepageHTML());
    }

    // Global search across all drives
    if (path === '/search') {
      if (!config.auth.search_all_drives) {
        return redirectResponse('/0:search' + (url.search || ''));
      }
      const q = url.searchParams.get('q')?.replace(/['"]/g, '') || '';
      return htmlResponse(getGlobalSearchHTML(q));
    }

    // Download handler
    if (path === '/download.aspx') {
      return handleDownload(request, userIp);
    }

    // Find path by ID - try ALL drives directly
    if (path === '/findpath') {
      const id = url.searchParams.get('id');
      const view = url.searchParams.get('view') === 'true';
      if (!id) return htmlResponse(getErrorHTML(400, 'Missing ID'), 400);
      await initDrives();
      const allDrives = getAllDrives();
      for (const d of allDrives) {
        try {
          const result = await d.findPathById(id);
          if (result) {
            const [fpath, prefix] = result;
            return redirectResponse(`/${prefix}:${fpath}${view ? '?a=view' : ''}`);
          }
        } catch { /* try next */ }
      }
      // No drive found it - fallback
      const encryptedId = await encryptString(id);
      return redirectResponse(`/fallback?id=${encryptedId}`);
    }

    // Fallback route for ID-based access
    if (path === '/fallback') {
      return htmlResponse(getMainHTML(0, { is_search_page: false, root_type: 1 }));
    }

    // Drive-specific routes: /{num}:{command}
    const driveMatch = path.match(/^\/(\d+):(\w+)(\/.*)?$/);
    if (driveMatch) {
      const driveIndex = parseInt(driveMatch[1]);
      const command = driveMatch[2];
      const drive = getDrive(driveIndex);
      
      if (!drive) return htmlResponse(getErrorHTML(404, 'Drive not found'), 404);

      switch (command) {
        case 'search':
          return handleSearch(request, drive, userIp);
        case 'id2path':
          return handleId2Path(request, drive);
        case 'fallback':
          return handleFallback(request, drive, userIp);
        case 'findpath':
          return handleFindPath(request, drive, url);
      }
    }

    // Path-based routes: /{num}:/path/to/file
    const pathMatch = path.match(/^\/(\d+):\/(.*)$/);
    if (pathMatch) {
      const driveIndex = parseInt(pathMatch[1]);
      const drivePath = '/' + pathMatch[2];
      const drive = getDrive(driveIndex);
      
      if (!drive) return htmlResponse(getErrorHTML(404, 'Drive not found'), 404);

      // POST = API request (listing or file info)
      if (request.method === 'POST') {
        // Clone request to peek at body
        const body = await request.json() as any;
        
        // If body has 'path' field, it's a file info request from file() function
        if (body.path) {
          return handleFileInfoRequest(drive, drivePath, userIp);
        }
        
        // Otherwise it's a listing request
        return handleListRequest(body, drive, drivePath, userIp);
      }

      // GET with ?a=view = render view page
      const action = url.searchParams.get('a');
      const isDownload = url.searchParams.get('download') === 'true';
      
      if (drivePath.endsWith('/')) {
        return htmlResponse(getMainHTML(drive.order, { is_search_page: false, root_type: drive.root_type }));
      }

      // ?download=true on a path = path-based download (works in both modes)
      if (isDownload) {
        return handlePathDownload(request, drive, drivePath);
      }

      // ?a=view = render the view page
      if (action) {
        return htmlResponse(getMainHTML(drive.order, { is_search_page: false, root_type: drive.root_type }));
      }

      // No query params on a file path = direct download in path mode, view in id mode
      if (config.download_mode === 'path') {
        return handlePathDownload(request, drive, drivePath);
      }

      return htmlResponse(getMainHTML(drive.order, { is_search_page: false, root_type: drive.root_type }));
    }

    // Default: redirect to first drive or show error if no drives
    if (config.auth.roots.length === 0) {
      return htmlResponse(getErrorHTML(404, 'No drives configured. Please add drives in the admin panel.'), 404);
    }
    return redirectResponse('/0:/');
  } catch (error) {
    console.error('Request error:', error);
    return htmlResponse(getErrorHTML(500, 'Internal Server Error'), 500);
  }
}

async function handleDownload(request: Request, userIp: string): Promise<Response> {
  const url = new URL(request.url);
  const encryptedFile = url.searchParams.get('file');
  const encryptedExpiry = url.searchParams.get('expiry');
  const mac = url.searchParams.get('mac');

  if (!encryptedFile || !encryptedExpiry || !mac) {
    return htmlResponse(getErrorHTML(400, 'Invalid download link'), 400);
  }

  const verified = await verifyDownloadLink(encryptedFile, encryptedExpiry, mac, userIp);
  if (!verified) {
    return htmlResponse(getErrorHTML(401, 'Invalid or expired download link'), 401);
  }

  const range = request.headers.get('Range') || '';
  const inline = url.searchParams.get('inline') === 'true';
  
  return downloadFile(verified.fileId, range, inline);
}

async function handlePathDownload(request: Request, drive: GoogleDrive, path: string): Promise<Response> {
  const file = await drive.getSingleFile(path);
  if (!file) {
    return htmlResponse(getErrorHTML(404, 'File not found'), 404);
  }

  const range = request.headers.get('Range') || '';
  const inline = new URL(request.url).searchParams.get('inline') === 'true';
  
  return downloadFile(file.id, range, inline);
}

async function downloadFile(fileId: string, range: string, inline: boolean): Promise<Response> {
  const drives = getAllDrives();
  const drive = drives[0];
  
  const file = await drive.findItemById(fileId);
  if (!file?.name) {
    return jsonResponse({ error: 'File not found' }, 404);
  }

  const url = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
  const token = await (await import('../services/drive')).getAccessToken();
  
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Range: range
    }
  });

  if (!response.ok) {
    return htmlResponse(getErrorHTML(response.status, 'Download failed'), response.status);
  }

  const headers = new Headers(response.headers);
  headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename="${file.name}"`);
  if (file.size) headers.set('Content-Length', file.size);
  if (config.auth.enable_cors_file_down) headers.set('Access-Control-Allow-Origin', '*');

  return new Response(response.body, { status: response.status, headers });
}

/**
 * Handle file info request (when client sends POST with {path: "..."})
 * Returns file metadata with encrypted ID and download link
 */
async function handleFileInfoRequest(drive: GoogleDrive, drivePath: string, userIp: string): Promise<Response> {
  const file = await drive.getSingleFile(drivePath);
  if (!file) {
    return jsonResponse({ error: 'File not found' }, 404);
  }

  const encryptedId = await encryptString(file.id);
  const encryptedDriveId = file.driveId ? await encryptString(file.driveId) : '';
  let link: string | undefined;
  if (file.mimeType !== 'application/vnd.google-apps.folder') {
    link = config.download_mode === 'path'
      ? `/${drive.order}:${drivePath}?download=true`
      : await generateDownloadLink(file.id, userIp);
  }

  return jsonResponse({
    ...file,
    id: encryptedId,
    driveId: encryptedDriveId,
    link
  });
}

function generatePathLink(path: string, fileName: string, driveOrder: number): string {
  const encodedName = encodeURIComponent(fileName).replace(/%2F/g, '/');
  return `/${driveOrder}:${path}${encodedName}?download=true`;
}

async function handleListRequest(body: ListRequestBody, drive: GoogleDrive, path: string, userIp: string): Promise<Response> {
  const result = await drive.listFiles(path, body.page_token || undefined, body.page_index || 0);
  const usePathLinks = config.download_mode === 'path';

  // Encrypt file IDs and generate download links
  const encryptedFiles = await Promise.all(result.data.files.map(async (file) => {
    const encryptedId = await encryptString(file.id);
    const encryptedDriveId = file.driveId ? await encryptString(file.driveId) : '';
    let link: string | undefined;
    if (file.mimeType !== 'application/vnd.google-apps.folder') {
      link = usePathLinks 
        ? generatePathLink(path, file.name, drive.order)
        : await generateDownloadLink(file.id, userIp);
    }

    return { ...file, id: encryptedId, driveId: encryptedDriveId, link };
  }));

  return jsonResponse({
    nextPageToken: result.nextPageToken,
    curPageIndex: result.curPageIndex,
    data: { files: encryptedFiles }
  });
}

async function handleSearch(request: Request, drive: GoogleDrive, userIp: string): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === 'GET') {
    const q = url.searchParams.get('q')?.replace(/['"]/g, '') || '';
    return htmlResponse(getMainHTML(drive.order, { is_search_page: true, q, root_type: drive.root_type }));
  }

  const body = await request.json() as SearchRequestBody;
  if (!body.q) {
    return jsonResponse({ nextPageToken: null, curPageIndex: 0, data: { files: [] } });
  }

  const result = await drive.search(body.q, body.page_token || undefined, body.page_index || 0);
  if (!result.data) {
    return jsonResponse(result);
  }

  const encryptedFiles = await Promise.all(result.data.files.map(async (file) => {
    const encryptedId = await encryptString(file.id);
    const encryptedDriveId = file.driveId ? await encryptString(file.driveId) : '';
    const link = await generateDownloadLink(file.id, userIp);
    return { ...file, id: encryptedId, driveId: encryptedDriveId, link };
  }));

  return jsonResponse({ ...result, data: { files: encryptedFiles } });
}

async function handleId2Path(request: Request, drive: GoogleDrive): Promise<Response> {
  const body = await request.json() as { id: string };
  const decryptedId = await decryptString(body.id);
  const result = await drive.findPathById(decryptedId);
  
  if (!result) {
    return jsonResponse({ error: 'Path not found' }, 404);
  }

  const [path, prefix] = result;
  return jsonResponse({ path: `/${prefix}:${path}` });
}

async function handleFallback(request: Request, drive: GoogleDrive, userIp: string): Promise<Response> {
  const body = await request.json() as ListRequestBody;
  const decryptedId = await decryptString(body.id || '');

  if (body.type === 'folder') {
    // Try all drives to list this folder
    const allDrives = getAllDrives();
    let result = null;
    for (const d of allDrives) {
      try {
        const r = await d.listFilesById(decryptedId, body.page_token || undefined, body.page_index || 0);
        if (r.data.files.length > 0) { result = r; break; }
        if (!result) result = r; // Keep first result even if empty
      } catch { /* try next */ }
    }
    if (!result) result = await drive.listFilesById(decryptedId, body.page_token || undefined, body.page_index || 0);
    const encryptedFiles = await Promise.all(result.data.files.map(async (file) => {
      const encryptedId = await encryptString(file.id);
      const encryptedDriveId = file.driveId ? await encryptString(file.driveId) : '';
      const link = file.mimeType !== 'application/vnd.google-apps.folder'
        ? await generateDownloadLink(file.id, userIp)
        : undefined;
      return { ...file, id: encryptedId, driveId: encryptedDriveId, link };
    }));
    return jsonResponse({ ...result, data: { files: encryptedFiles } });
  }

  // Try all drives to find this file
  let file = null;
  let foundDriveIndex = 0;
  const allDrives2 = getAllDrives();
  for (const d of allDrives2) {
    try {
      const f = await d.findItemById(decryptedId);
      if (f?.name) { file = f; foundDriveIndex = d.order; break; }
    } catch { /* try next */ }
  }
  if (!file) {
    return jsonResponse({ error: 'File not found' }, 404);
  }

  const link = await generateDownloadLink(file.id, userIp);
  const encryptedId = await encryptString(file.id);
  return jsonResponse({ ...file, id: encryptedId, link, parents: [null] });
}

async function handleFindPath(request: Request, drive: GoogleDrive, url: URL): Promise<Response> {
  const id = url.searchParams.get('id');
  const view = url.searchParams.get('view') === 'true';

  if (!id) {
    return htmlResponse(getErrorHTML(400, 'Missing ID'), 400);
  }

  // Try ALL drives to find the file path, not just the one from URL
  const allDrives = getAllDrives();
  for (const d of allDrives) {
    try {
      const result = await d.findPathById(id);
      if (result) {
        const [path, prefix] = result;
        const fullPath = `/${prefix}:${path}${view ? '?a=view' : ''}`;
        return redirectResponse(fullPath);
      }
    } catch { /* try next drive */ }
  }

  // None of the drives found it - use fallback with first drive that can access it
  const encryptedId = await encryptString(id);
  return redirectResponse(`/fallback?id=${encryptedId}`);
}
