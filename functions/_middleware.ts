// Middleware: Initialize DB tables if needed on first request
import { isSetupComplete } from './lib/db';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  secret_key TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  client_secret TEXT NOT NULL DEFAULT '',
  refresh_token TEXT NOT NULL DEFAULT '',
  root_folder_id TEXT NOT NULL DEFAULT 'root',
  is_shared_drive INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  auth_type TEXT NOT NULL DEFAULT 'oauth',
  credential_id INTEGER DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS service_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  json_data TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO config (key, value) VALUES ('site_name', 'Google Drive Index');
INSERT OR IGNORE INTO config (key, value) VALUES ('items_per_page', '50');
INSERT OR IGNORE INTO config (key, value) VALUES ('allow_search', '1');
INSERT OR IGNORE INTO config (key, value) VALUES ('allow_download', '1');
INSERT OR IGNORE INTO config (key, value) VALUES ('auth_enabled', '0');
INSERT OR IGNORE INTO config (key, value) VALUES ('theme', 'dark');
`;

let dbInitialized = false;

export const onRequest: PagesFunction<{ DB: D1Database }> = async (context) => {
  // Auto-initialize DB tables on first request
  if (!dbInitialized && context.env.DB) {
    try {
      // Check if tables exist by trying a simple query
      await context.env.DB.prepare('SELECT 1 FROM config LIMIT 1').first();
      dbInitialized = true;
    } catch {
      // Tables don't exist, create them
      try {
        const statements = SCHEMA.split(';').filter(s => s.trim()).map(s => context.env.DB.prepare(s.trim()));
        await context.env.DB.batch(statements);
        dbInitialized = true;
      } catch (e) {
        console.error('DB init error:', e);
      }
    }
  }

  // Add CORS headers for API routes
  const url = new URL(context.request.url);
  if (url.pathname.startsWith('/api/')) {
    if (context.request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const response = await context.next();
    response.headers.set('Access-Control-Allow-Origin', '*');
    return response;
  }

  return context.next();
};