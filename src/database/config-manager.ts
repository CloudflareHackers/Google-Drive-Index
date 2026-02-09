import { DriveConfig, SiteConfig, GlobalCredential } from './schema';

export class ConfigManager {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  // ==================== Initialization ====================
  async initialize(): Promise<void> {
    // Create tables
    await this.db
      .prepare(
        `
      CREATE TABLE IF NOT EXISTS site_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `,
      )
      .run();

    await this.db
      .prepare(
        `
      CREATE TABLE IF NOT EXISTS drives (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        drive_type TEXT NOT NULL DEFAULT 'personal',
        drive_id TEXT NOT NULL DEFAULT '',
        credential_id TEXT DEFAULT NULL,
        client_id TEXT NOT NULL DEFAULT '',
        client_secret TEXT NOT NULL DEFAULT '',
        refresh_token TEXT NOT NULL DEFAULT '',
        auth_type TEXT NOT NULL DEFAULT 'refresh_token',
        service_account TEXT DEFAULT NULL,
        root_folder_id TEXT DEFAULT NULL,
        display_order INTEGER NOT NULL DEFAULT 0,
        password TEXT DEFAULT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `,
      )
      .run();

    await this.db
      .prepare(
        `
      CREATE TABLE IF NOT EXISTS global_credentials (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        is_default INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `,
      )
      .run();

    await this.db
      .prepare(
        `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )
    `,
      )
      .run();

    // Migrate existing tables - add new columns if they don't exist
    try {
      await this.db.prepare(`ALTER TABLE drives ADD COLUMN credential_id TEXT DEFAULT NULL`).run();
    } catch (_e) {
      /* column already exists */
    }
    try {
      await this.db
        .prepare(`ALTER TABLE drives ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'refresh_token'`)
        .run();
    } catch (_e) {
      /* column already exists */
    }

    // Set defaults
    const defaults: Record<string, string> = {
      site_name: 'Google Drive Index',
      site_description: 'A fast Google Drive directory listing',
      theme: 'darkly',
      custom_css: '',
      custom_js: '',
      allow_signup: 'false',
      require_auth: 'false',
      files_per_page: '50',
      enable_search: 'true',
      enable_readme: 'true',
      enable_thumbnails: 'true',
      download_method: 'path',
    };

    for (const [key, value] of Object.entries(defaults)) {
      await this.db
        .prepare(
          `
        INSERT OR IGNORE INTO site_config (key, value) VALUES (?, ?)
      `,
        )
        .bind(key, value)
        .run();
    }
  }

  // ==================== Site Config ====================
  async getSiteConfig(): Promise<SiteConfig> {
    const rows = await this.db.prepare('SELECT key, value FROM site_config').all();
    const config: Record<string, string> = {};
    for (const row of rows.results as Array<{ key: string; value: string }>) {
      config[row.key] = row.value;
    }
    return {
      site_name: config.site_name || 'Google Drive Index',
      site_description: config.site_description || '',
      theme: config.theme || 'darkly',
      custom_css: config.custom_css || '',
      custom_js: config.custom_js || '',
      allow_signup: config.allow_signup === 'true',
      require_auth: config.require_auth === 'true',
      files_per_page: parseInt(config.files_per_page || '50', 10),
      enable_search: config.enable_search !== 'false',
      enable_readme: config.enable_readme !== 'false',
      enable_thumbnails: config.enable_thumbnails !== 'false',
      download_method: (config.download_method as 'file' | 'path') || 'path',
      admin_password_hash: config.admin_password_hash || '',
      created_at: config.created_at || new Date().toISOString(),
      updated_at: config.updated_at || new Date().toISOString(),
    } as SiteConfig;
  }

  async updateSiteConfig(key: string, value: string): Promise<void> {
    await this.db
      .prepare(
        `
      INSERT INTO site_config (key, value, updated_at) 
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
    `,
      )
      .bind(key, value, value)
      .run();
  }

  async bulkUpdateSiteConfig(updates: Record<string, string>): Promise<void> {
    for (const [key, value] of Object.entries(updates)) {
      await this.updateSiteConfig(key, value);
    }
  }

  // ==================== Global Credentials ====================
  async getGlobalCredentials(): Promise<GlobalCredential[]> {
    const result = await this.db
      .prepare('SELECT * FROM global_credentials ORDER BY is_default DESC, created_at ASC')
      .all();
    return (result.results || []) as unknown as GlobalCredential[];
  }

  async getGlobalCredential(id: string): Promise<GlobalCredential | null> {
    const result = await this.db
      .prepare('SELECT * FROM global_credentials WHERE id = ?')
      .bind(id)
      .first();
    return (result as unknown as GlobalCredential) || null;
  }

  async getDefaultCredential(): Promise<GlobalCredential | null> {
    const result = await this.db
      .prepare('SELECT * FROM global_credentials WHERE is_default = 1 LIMIT 1')
      .first();
    return (result as unknown as GlobalCredential) || null;
  }

  async addGlobalCredential(cred: Omit<GlobalCredential, 'created_at' | 'updated_at'>): Promise<void> {
    // If this is set as default, unset other defaults
    if (cred.is_default) {
      await this.db.prepare('UPDATE global_credentials SET is_default = 0').run();
    }
    await this.db
      .prepare(
        `INSERT INTO global_credentials (id, name, client_id, client_secret, refresh_token, is_default) 
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(cred.id, cred.name, cred.client_id, cred.client_secret, cred.refresh_token, cred.is_default ? 1 : 0)
      .run();
  }

  async updateGlobalCredential(
    id: string,
    updates: Partial<Omit<GlobalCredential, 'id' | 'created_at' | 'updated_at'>>,
  ): Promise<void> {
    if (updates.is_default) {
      await this.db.prepare('UPDATE global_credentials SET is_default = 0').run();
    }
    const fields: string[] = [];
    const values: (string | number)[] = [];
    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.client_id !== undefined) {
      fields.push('client_id = ?');
      values.push(updates.client_id);
    }
    if (updates.client_secret !== undefined) {
      fields.push('client_secret = ?');
      values.push(updates.client_secret);
    }
    if (updates.refresh_token !== undefined) {
      fields.push('refresh_token = ?');
      values.push(updates.refresh_token);
    }
    if (updates.is_default !== undefined) {
      fields.push('is_default = ?');
      values.push(updates.is_default ? 1 : 0);
    }
    if (fields.length === 0) return;
    fields.push("updated_at = datetime('now')");
    values.push(id);
    await this.db.prepare(`UPDATE global_credentials SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
  }

  async deleteGlobalCredential(id: string): Promise<void> {
    // Check if any drives use this credential
    const drives = await this.db
      .prepare('SELECT COUNT(*) as count FROM drives WHERE credential_id = ?')
      .bind(id)
      .first();
    if (drives && (drives as Record<string, number>).count > 0) {
      throw new Error('Cannot delete credential that is in use by drives. Update those drives first.');
    }
    await this.db.prepare('DELETE FROM global_credentials WHERE id = ?').bind(id).run();
  }

  // ==================== Drives ====================
  async getDrives(): Promise<DriveConfig[]> {
    const result = await this.db.prepare('SELECT * FROM drives ORDER BY display_order ASC').all();
    return (result.results || []).map((row: Record<string, unknown>) => ({
      id: row.id as string,
      name: row.name as string,
      drive_type: row.drive_type as 'personal' | 'shared' | 'sub-folder',
      drive_id: row.drive_id as string,
      credential_id: (row.credential_id as string) || undefined,
      client_id: row.client_id as string,
      client_secret: row.client_secret as string,
      refresh_token: row.refresh_token as string,
      auth_type: (row.auth_type as 'refresh_token' | 'service_account') || 'refresh_token',
      service_account: (row.service_account as string) || undefined,
      root_folder_id: (row.root_folder_id as string) || undefined,
      order: row.display_order as number,
      password: (row.password as string) || undefined,
      enabled: row.enabled === 1,
      created_at: row.created_at as string,
      updated_at: row.updated_at as string,
    }));
  }

  async getDrive(id: string): Promise<DriveConfig | null> {
    const row = (await this.db.prepare('SELECT * FROM drives WHERE id = ?').bind(id).first()) as Record<
      string,
      unknown
    > | null;
    if (!row) return null;
    return {
      id: row.id as string,
      name: row.name as string,
      drive_type: row.drive_type as 'personal' | 'shared' | 'sub-folder',
      drive_id: row.drive_id as string,
      credential_id: (row.credential_id as string) || undefined,
      client_id: row.client_id as string,
      client_secret: row.client_secret as string,
      refresh_token: row.refresh_token as string,
      auth_type: (row.auth_type as 'refresh_token' | 'service_account') || 'refresh_token',
      service_account: (row.service_account as string) || undefined,
      root_folder_id: (row.root_folder_id as string) || undefined,
      order: row.display_order as number,
      password: (row.password as string) || undefined,
      enabled: row.enabled === 1,
      created_at: row.created_at as string,
      updated_at: row.updated_at as string,
    };
  }

  async addDrive(drive: Omit<DriveConfig, 'created_at' | 'updated_at'>): Promise<void> {
    await this.db
      .prepare(
        `
      INSERT INTO drives (id, name, drive_type, drive_id, credential_id, client_id, client_secret, refresh_token, auth_type, service_account, root_folder_id, display_order, password, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      )
      .bind(
        drive.id,
        drive.name,
        drive.drive_type,
        drive.drive_id,
        drive.credential_id || null,
        drive.client_id,
        drive.client_secret,
        drive.refresh_token,
        drive.auth_type || 'refresh_token',
        drive.service_account || null,
        drive.root_folder_id || null,
        drive.order,
        drive.password || null,
        drive.enabled ? 1 : 0,
      )
      .run();
  }

  async updateDrive(
    id: string,
    updates: Partial<Omit<DriveConfig, 'id' | 'created_at' | 'updated_at'>>,
  ): Promise<void> {
    const fields: string[] = [];
    const values: (string | number | null)[] = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.drive_type !== undefined) {
      fields.push('drive_type = ?');
      values.push(updates.drive_type);
    }
    if (updates.drive_id !== undefined) {
      fields.push('drive_id = ?');
      values.push(updates.drive_id);
    }
    if (updates.credential_id !== undefined) {
      fields.push('credential_id = ?');
      values.push(updates.credential_id || null);
    }
    if (updates.client_id !== undefined) {
      fields.push('client_id = ?');
      values.push(updates.client_id);
    }
    if (updates.client_secret !== undefined) {
      fields.push('client_secret = ?');
      values.push(updates.client_secret);
    }
    if (updates.refresh_token !== undefined) {
      fields.push('refresh_token = ?');
      values.push(updates.refresh_token);
    }
    if (updates.auth_type !== undefined) {
      fields.push('auth_type = ?');
      values.push(updates.auth_type);
    }
    if (updates.service_account !== undefined) {
      fields.push('service_account = ?');
      values.push(updates.service_account || null);
    }
    if (updates.root_folder_id !== undefined) {
      fields.push('root_folder_id = ?');
      values.push(updates.root_folder_id || null);
    }
    if (updates.order !== undefined) {
      fields.push('display_order = ?');
      values.push(updates.order);
    }
    if (updates.password !== undefined) {
      fields.push('password = ?');
      values.push(updates.password || null);
    }
    if (updates.enabled !== undefined) {
      fields.push('enabled = ?');
      values.push(updates.enabled ? 1 : 0);
    }

    if (fields.length === 0) return;

    fields.push("updated_at = datetime('now')");
    values.push(id);

    await this.db.prepare(`UPDATE drives SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
  }

  async deleteDrive(id: string): Promise<void> {
    await this.db.prepare('DELETE FROM drives WHERE id = ?').bind(id).run();
  }

  async reorderDrives(driveIds: string[]): Promise<void> {
    for (let i = 0; i < driveIds.length; i++) {
      await this.db
        .prepare("UPDATE drives SET display_order = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(i, driveIds[i])
        .run();
    }
  }

  // ==================== Admin Auth ====================
  async getAdminPasswordHash(): Promise<string | null> {
    const result = (await this.db
      .prepare("SELECT value FROM site_config WHERE key = 'admin_password_hash'")
      .first()) as { value: string } | null;
    return result?.value || null;
  }

  async setAdminPasswordHash(hash: string): Promise<void> {
    await this.updateSiteConfig('admin_password_hash', hash);
  }

  async isSetupComplete(): Promise<boolean> {
    const hash = await this.getAdminPasswordHash();
    return !!hash && hash.length > 0;
  }

  // ==================== Resolve Drive Credentials ====================
  async resolveDriveCredentials(
    drive: DriveConfig,
  ): Promise<{ client_id: string; client_secret: string; refresh_token: string }> {
    // If drive has a credential_id, fetch from global credentials
    if (drive.credential_id) {
      const cred = await this.getGlobalCredential(drive.credential_id);
      if (cred) {
        return {
          client_id: cred.client_id,
          client_secret: cred.client_secret,
          refresh_token: cred.refresh_token,
        };
      }
    }
    // If drive has its own credentials, use those
    if (drive.client_id && drive.client_secret && drive.refresh_token) {
      return {
        client_id: drive.client_id,
        client_secret: drive.client_secret,
        refresh_token: drive.refresh_token,
      };
    }
    // Fallback to default global credential
    const defaultCred = await this.getDefaultCredential();
    if (defaultCred) {
      return {
        client_id: defaultCred.client_id,
        client_secret: defaultCred.client_secret,
        refresh_token: defaultCred.refresh_token,
      };
    }
    throw new Error(`No credentials found for drive: ${drive.name}`);
  }
}