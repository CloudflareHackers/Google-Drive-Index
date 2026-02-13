// Database helper functions

export interface Env {
  DB: D1Database;
}

export interface Admin {
  id: number;
  username: string;
  password_hash: string;
  secret_key: string;
  created_at: string;
}

export interface DriveConfig {
  id: number;
  name: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  root_folder_id: string;
  is_shared_drive: number;
  enabled: number;
  sort_order: number;
  created_at: string;
}

export interface ConfigEntry {
  key: string;
  value: string;
}

// Check if initial setup has been completed
export async function isSetupComplete(db: D1Database): Promise<boolean> {
  const admin = await db.prepare('SELECT id FROM admin WHERE id = 1').first();
  return !!admin;
}

// Get admin record
export async function getAdmin(db: D1Database): Promise<Admin | null> {
  return await db.prepare('SELECT * FROM admin WHERE id = 1').first<Admin>();
}

// Create admin (first-time setup)
export async function createAdmin(db: D1Database, username: string, passwordHash: string, secretKey: string): Promise<void> {
  await db.prepare('INSERT OR REPLACE INTO admin (id, username, password_hash, secret_key) VALUES (1, ?, ?, ?)').bind(username, passwordHash, secretKey).run();
}

// Get config value
export async function getConfig(db: D1Database, key: string): Promise<string | null> {
  const row = await db.prepare('SELECT value FROM config WHERE key = ?').bind(key).first<ConfigEntry>();
  return row ? row.value : null;
}

// Set config value
export async function setConfig(db: D1Database, key: string, value: string): Promise<void> {
  await db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').bind(key, value).run();
}

// Get all config as object
export async function getAllConfig(db: D1Database): Promise<Record<string, string>> {
  const rows = await db.prepare('SELECT key, value FROM config').all<ConfigEntry>();
  const config: Record<string, string> = {};
  for (const row of rows.results) {
    config[row.key] = row.value;
  }
  return config;
}

// Get all drives
export async function getDrives(db: D1Database, enabledOnly = false): Promise<DriveConfig[]> {
  const query = enabledOnly
    ? 'SELECT * FROM drives WHERE enabled = 1 ORDER BY sort_order ASC, id ASC'
    : 'SELECT * FROM drives ORDER BY sort_order ASC, id ASC';
  const rows = await db.prepare(query).all<DriveConfig>();
  return rows.results;
}

// Get drive by ID
export async function getDrive(db: D1Database, id: number): Promise<DriveConfig | null> {
  return await db.prepare('SELECT * FROM drives WHERE id = ?').bind(id).first<DriveConfig>();
}

// Add a drive
export async function addDrive(db: D1Database, drive: Omit<DriveConfig, 'id' | 'created_at'>): Promise<number> {
  const result = await db.prepare(
    'INSERT INTO drives (name, client_id, client_secret, refresh_token, root_folder_id, is_shared_drive, enabled, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    drive.name, drive.client_id, drive.client_secret, drive.refresh_token,
    drive.root_folder_id, drive.is_shared_drive, drive.enabled, drive.sort_order
  ).run();
  return result.meta.last_row_id as number;
}

// Update drive
export async function updateDrive(db: D1Database, id: number, drive: Partial<Omit<DriveConfig, 'id' | 'created_at'>>): Promise<void> {
  const fields: string[] = [];
  const values: any[] = [];
  for (const [key, value] of Object.entries(drive)) {
    if (value !== undefined) {
      fields.push(`${key} = ?`);
      values.push(value);
    }
  }
  if (fields.length === 0) return;
  values.push(id);
  await db.prepare(`UPDATE drives SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
}

// Delete drive
export async function deleteDrive(db: D1Database, id: number): Promise<void> {
  await db.prepare('DELETE FROM drives WHERE id = ?').bind(id).run();
}