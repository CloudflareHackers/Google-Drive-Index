-- Google Drive Index - D1 Schema

-- Admin credentials (set during first-time setup)
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  secret_key TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Site configuration (key-value store)
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Google Drive accounts (multi-drive support)
CREATE TABLE IF NOT EXISTS drives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  root_folder_id TEXT NOT NULL DEFAULT 'root',
  is_shared_drive INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Insert default config values
INSERT OR IGNORE INTO config (key, value) VALUES ('site_name', 'Google Drive Index');
INSERT OR IGNORE INTO config (key, value) VALUES ('items_per_page', '50');
INSERT OR IGNORE INTO config (key, value) VALUES ('allow_search', '1');
INSERT OR IGNORE INTO config (key, value) VALUES ('allow_download', '1');
INSERT OR IGNORE INTO config (key, value) VALUES ('auth_enabled', '0');
INSERT OR IGNORE INTO config (key, value) VALUES ('theme', 'dark');