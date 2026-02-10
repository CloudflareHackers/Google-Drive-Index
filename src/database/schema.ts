/**
 * Database Schema SQL & Type Definitions
 * @version 3.1.0
 */

// ============================================================================
// TypeScript Interfaces
// ============================================================================

export interface DriveConfig {
  id: string;
  name: string;
  drive_type: 'personal' | 'shared' | 'sub-folder';
  drive_id: string;
  credential_id?: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  auth_type: 'refresh_token' | 'service_account';
  service_account?: string;
  root_folder_id?: string;
  order: number;
  password?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface GlobalCredential {
  id: string;
  name: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface SiteConfig {
  site_name: string;
  site_description: string;
  theme: string;
  custom_css: string;
  custom_js: string;
  allow_signup: boolean;
  require_auth: boolean;
  files_per_page: number;
  enable_search: boolean;
  enable_readme: boolean;
  enable_thumbnails: boolean;
  download_method: 'file' | 'path';
  admin_password_hash: string;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// D1 Schema SQL
// ============================================================================

export const D1_SCHEMA = `
-- Configuration table
CREATE TABLE IF NOT EXISTS config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('auth', 'ui', 'player', 'security', 'drives', 'system')),
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_config_key ON config(key);
CREATE INDEX IF NOT EXISTS idx_config_category ON config(category);

-- Drives table
CREATE TABLE IF NOT EXISTS drives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  drive_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  order_index INTEGER NOT NULL DEFAULT 0,
  protect_file_link INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_drives_enabled ON drives(enabled);
CREATE INDEX IF NOT EXISTS idx_drives_order ON drives(order_index);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email TEXT,
  role TEXT NOT NULL CHECK(role IN ('admin', 'user')) DEFAULT 'user',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);

-- Service Accounts table
CREATE TABLE IF NOT EXISTS service_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  client_email TEXT NOT NULL UNIQUE,
  private_key TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sa_enabled ON service_accounts(enabled);

-- Setup state table
CREATE TABLE IF NOT EXISTS setup_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  completed INTEGER NOT NULL DEFAULT 0,
  current_step INTEGER NOT NULL DEFAULT 1,
  setup_data TEXT,
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default setup state
INSERT OR IGNORE INTO setup_state (id, completed, current_step) VALUES (1, 0, 1);

-- Sessions table (for user sessions)
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_token TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`;

export const HYPERDRIVE_SCHEMA = `
-- Configuration table (PostgreSQL/MySQL compatible)
CREATE TABLE IF NOT EXISTS config (
  id SERIAL PRIMARY KEY,
  key VARCHAR(255) NOT NULL UNIQUE,
  value TEXT NOT NULL,
  category VARCHAR(50) NOT NULL CHECK(category IN ('auth', 'ui', 'player', 'security', 'drives', 'system')),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_config_key ON config(key);
CREATE INDEX IF NOT EXISTS idx_config_category ON config(category);

-- Drives table
CREATE TABLE IF NOT EXISTS drives (
  id SERIAL PRIMARY KEY,
  drive_id VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  order_index INTEGER NOT NULL DEFAULT 0,
  protect_file_link BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_drives_enabled ON drives(enabled);
CREATE INDEX IF NOT EXISTS idx_drives_order ON drives(order_index);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(255),
  role VARCHAR(20) NOT NULL CHECK(role IN ('admin', 'user')) DEFAULT 'user',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);

-- Service Accounts table
CREATE TABLE IF NOT EXISTS service_accounts (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  client_email VARCHAR(255) NOT NULL UNIQUE,
  private_key TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sa_enabled ON service_accounts(enabled);

-- Setup state table
CREATE TABLE IF NOT EXISTS setup_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  completed BOOLEAN NOT NULL DEFAULT FALSE,
  current_step INTEGER NOT NULL DEFAULT 1,
  setup_data TEXT,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default setup state
INSERT INTO setup_state (id, completed, current_step) VALUES (1, FALSE, 1) ON CONFLICT DO NOTHING;

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  session_token VARCHAR(255) NOT NULL UNIQUE,
  username VARCHAR(255) NOT NULL,
  ip_address VARCHAR(50),
  user_agent TEXT,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`;

export const DEFAULT_CONFIG_VALUES = {
  'system.backend': 'static',
  'system.version': '3.0.0',
  'system.environment': 'production',
  'auth.siteName': 'Google Drive Index',
  'auth.enable_login': 'false',
  'auth.enable_signup': 'false',
  'auth.login_days': '7',
  'auth.files_list_page_size': '100',
  'auth.search_result_list_page_size': '100',
  'security.crypto_base_key': '',
  'security.hmac_base_key': '',
  'security.file_link_expiry': '7',
  'security.enable_ip_lock': 'false',
  'ui.theme': 'darkly',
  'ui.logo_image': 'true',
  'ui.display_size': 'true',
  'ui.display_time': 'false',
  'ui.display_download': 'true',
  'player.player': 'videojs',
  'player.videojs_version': '8.3.0'
};