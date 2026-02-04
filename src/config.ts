/**
 * Application Configuration
 * Edit this file to configure your Google Drive Index
 * @version 3.0.0
 */

import type { AppConfig, ServiceAccount, DriveRoot } from './types';

// ============================================================================
// SERVICE ACCOUNTS
// Add multiple service accounts for load balancing (optional)
// Format: { ...service_account_json_content }
// ============================================================================
const serviceAccounts: ServiceAccount[] = [
  // Paste your service account JSON content here
  // Example:
  // {
  //   "type": "service_account",
  //   "project_id": "your-project",
  //   "private_key_id": "...",
  //   "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  //   "client_email": "...",
  //   "client_id": "...",
  //   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  //   "token_uri": "https://oauth2.googleapis.com/token",
  //   "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  //   "client_x509_cert_url": "..."
  // }
];

// ============================================================================
// DRIVE ROOTS
// Add your Google Drive folder/drive IDs here
// ============================================================================
const driveRoots: DriveRoot[] = [
  {
    id: '', // Google Drive folder ID or 'root' for My Drive
    name: 'My Drive',
    protect_file_link: false
  },
  // Add more drives as needed:
  // {
  //   id: 'SHARED_DRIVE_ID',
  //   name: 'Shared Drive',
  //   protect_file_link: false
  // }
];

// ============================================================================
// DOWNLOAD DOMAINS (for load balancing)
// Add multiple worker URLs to distribute download traffic
// ============================================================================
const downloadDomains: string[] = [
  '' // Leave empty to use current domain, or add: 'https://worker1.example.workers.dev'
];

// ============================================================================
// BLOCKED REGIONS & ASNs
// ============================================================================
const blockedRegions: string[] = [
  // Add country codes: 'IN', 'US', 'PK'
];

const blockedASNs: number[] = [
  // Add ASN numbers from http://www.bgplookingglass.com/list-of-autonomous-system-numbers
];

// ============================================================================
// CRYPTOGRAPHIC KEYS (IMPORTANT: Generate your own!)
// ============================================================================
// Generate using: crypto.getRandomValues(new Uint8Array(32))
const CRYPTO_BASE_KEY = '3225f86e99e205347b4310e437253bfd'; // 256-bit key for AES encryption
const HMAC_BASE_KEY = '4d1fbf294186b82d74fff2494c04012364200263d6a36123db0bd08d6be1423c'; // 256-bit key for HMAC
const ENCRYPT_IV = new Uint8Array([247, 254, 106, 195, 32, 148, 131, 244, 222, 133, 26, 182, 20, 138, 215, 81]) as Uint8Array<ArrayBuffer>; // 128-bit IV

// ============================================================================
// MAIN CONFIGURATION
// ============================================================================
export const config: AppConfig = {
  // Environment: 'production' | 'development' | 'local'
  environment: 'production',

  // Backend selection: 'static' | 'd1' | 'hyperdrive'
  // Change this to use database-backed configuration
  configBackend: 'static' as any,

  // Service accounts for API access
  serviceaccounts: serviceAccounts,

  // Download domains for load balancing
  domains_for_dl: downloadDomains,

  // Region/ASN blocking
  blocked_region: blockedRegions,
  blocked_asn: blockedASNs,

  // Download mode: 'path' for URL path-based, 'id' for direct ID-based
  download_mode: 'path',

  // Cryptographic keys
  crypto_base_key: CRYPTO_BASE_KEY,
  hmac_base_key: HMAC_BASE_KEY,
  encrypt_iv: ENCRYPT_IV,

  // ============================================================================
  // AUTHENTICATION CONFIGURATION
  // ============================================================================
  auth: {
    siteName: 'Google Drive Index',

    // OAuth2 credentials (for user account authentication)
    client_id: '',
    client_secret: '',
    refresh_token: '',

    // Service account settings
    service_account: serviceAccounts.length > 0,
    service_account_json: serviceAccounts.length > 0
      ? serviceAccounts[Math.floor(Math.random() * serviceAccounts.length)]
      : undefined,

    // Pagination settings
    files_list_page_size: 100,
    search_result_list_page_size: 100,

    // Security settings
    enable_cors_file_down: false,
    enable_password_file_verify: false,
    direct_link_protection: false,
    disable_anonymous_download: false,
    file_link_expiry: 7, // days

    // Search settings
    search_all_drives: true,

    // Login system
    enable_login: false,
    enable_signup: false,
    enable_social_login: false,
    google_client_id_for_login: '',
    google_client_secret_for_login: '',
    redirect_domain: '', // e.g., 'https://your-worker.workers.dev'
    login_database: 'Local', // 'Local' | 'KV' | 'MongoDB'
    login_days: 7,
    enable_ip_lock: false,
    single_session: false,
    ip_changed_action: false,

    // CORS settings
    cors_domain: '*',

    // Local user database (when login_database is 'Local')
    users_list: [
      { username: 'admin', password: 'admin' }
    ],

    // Drive roots
    roots: driveRoots
  },

  // ============================================================================
  // UI CONFIGURATION
  // ============================================================================
  ui: {
    theme: 'darkly', // Bootswatch theme
    version: '3.0.0',

    // Logo settings
    logo_image: true,
    logo_height: '',
    logo_width: '100px',
    favicon: '/favicon.ico',
    logo_link_name: '/logo.svg',
    login_image: '/login-logo.png',

    // Header settings
    fixed_header: true,
    header_padding: '80',
    nav_link_1: 'Home',
    nav_link_3: 'Current Path',
    nav_link_4: 'Contact',
    header_style_class: 'navbar-dark bg-primary',

    // Footer settings
    fixed_footer: false,
    hide_footer: true,
    footer_style_class: 'bg-primary',

    // Color settings
    css_a_tag_color: 'white',
    css_p_tag_color: 'white',
    folder_text_color: 'white',
    loading_spinner_class: 'text-light',
    search_button_class: 'btn btn-danger',
    path_nav_alert_class: 'alert alert-primary',
    file_view_alert_class: 'alert alert-danger',
    file_count_alert_class: 'alert alert-secondary',

    // Links
    contact_link: 'https://telegram.dog/Telegram',
    copyright_year: '2026',
    company_name: 'Google Drive Index',
    company_link: 'https://github.com',
    unauthorized_owner_link: 'https://telegram.dog/Telegram',
    unauthorized_owner_email: 'abuse@example.com',

    // Feature toggles
    credit: true,
    display_size: true,
    display_time: false,
    display_download: true,
    disable_player: false,
    disable_video_download: false,
    allow_selecting_files: true,
    second_domain_for_dl: false,

    // Media settings
    poster: '/poster.jpg',
    audioposter: '/music.jpg',
    render_head_md: true,
    render_readme_md: true,

    // Download domain (auto-selected from domains_for_dl)
    downloaddomain: downloadDomains.length > 0
      ? downloadDomains[Math.floor(Math.random() * downloadDomains.length)]
      : '',
    show_logout_button: false
  },

  // ============================================================================
  // VIDEO PLAYER CONFIGURATION
  // ============================================================================
  player: {
    player: 'videojs', // 'videojs' | 'plyr' | 'dplayer' | 'jwplayer'
    videojs_version: '8.3.0',
    plyr_io_version: '3.7.8',
    jwplayer_version: '8.16.2'
  }
};

// ============================================================================
// ADMIN PANEL CONFIGURATION
// ============================================================================
export const adminConfig = {
  enabled: true,
  username: 'admin',
  password: 'changeme123', // CHANGE THIS!
  sessionSecret: 'your-session-secret-change-this', // CHANGE THIS!
  sessionDuration: 24 * 60 * 60 * 1000 // 24 hours in milliseconds
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get a random service account (for load balancing)
 */
export function getRandomServiceAccount(): ServiceAccount | undefined {
  if (serviceAccounts.length === 0) return undefined;
  return serviceAccounts[Math.floor(Math.random() * serviceAccounts.length)];
}

/**
 * Get a random download domain (for load balancing)
 */
export function getRandomDownloadDomain(): string {
  if (downloadDomains.length === 0 || downloadDomains[0] === '') return '';
  return downloadDomains[Math.floor(Math.random() * downloadDomains.length)];
}

/**
 * Validate configuration
 */
export function validateConfig(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check for required credentials
  if (!config.auth.service_account && !config.auth.refresh_token) {
    errors.push('Either service_account or refresh_token must be configured');
  }

  // Check for drive roots
  if (config.auth.roots.length === 0) {
    errors.push('At least one drive root must be configured');
  }

  // Check for empty drive IDs
  config.auth.roots.forEach((root, index) => {
    if (!root.id) {
      errors.push(`Drive root at index ${index} has empty ID`);
    }
  });

  // Check crypto keys
  if (config.crypto_base_key === '3225f86e99e205347b4310e437253bfd') {
    errors.push('WARNING: Using default crypto_base_key. Generate your own for security!');
  }

  if (config.hmac_base_key === '4d1fbf294186b82d74fff2494c04012364200263d6a36123db0bd08d6be1423c') {
    errors.push('WARNING: Using default hmac_base_key. Generate your own for security!');
  }

  return {
    valid: errors.filter(e => !e.startsWith('WARNING')).length === 0,
    errors
  };
}

export default config;
