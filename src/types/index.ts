/**
 * Google Drive Index - Type Definitions
 * @version 3.0.0
 */

// ============================================================================
// Configuration Types
// ============================================================================

export interface ServiceAccount {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url: string;
  client_x509_cert_url: string;
}

export interface DriveRoot {
  id: string;
  name: string;
  protect_file_link?: boolean;
}

export interface UserCredentials {
  username: string;
  password: string;
}

export interface AuthConfig {
  siteName: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  service_account: boolean;
  service_account_json?: ServiceAccount;
  files_list_page_size: number;
  search_result_list_page_size: number;
  enable_cors_file_down: boolean;
  enable_password_file_verify: boolean;
  direct_link_protection: boolean;
  disable_anonymous_download: boolean;
  file_link_expiry: number;
  search_all_drives: boolean;
  enable_login: boolean;
  enable_signup: boolean;
  enable_social_login: boolean;
  google_client_id_for_login: string;
  google_client_secret_for_login: string;
  redirect_domain: string;
  login_database: 'Local' | 'KV' | 'MongoDB';
  login_days: number;
  enable_ip_lock: boolean;
  single_session: boolean;
  ip_changed_action: boolean;
  cors_domain: string;
  users_list: UserCredentials[];
  roots: DriveRoot[];
  // Runtime properties
  accessToken?: string;
  expires?: number;
  user_drive_real_root_id?: string;
}

export interface UIConfig {
  theme: string;
  version: string;
  logo_image: boolean;
  logo_height: string;
  logo_width: string;
  favicon: string;
  logo_link_name: string;
  login_image: string;
  fixed_header: boolean;
  header_padding: string;
  nav_link_1: string;
  nav_link_3: string;
  nav_link_4: string;
  fixed_footer: boolean;
  hide_footer: boolean;
  header_style_class: string;
  footer_style_class: string;
  css_a_tag_color: string;
  css_p_tag_color: string;
  folder_text_color: string;
  loading_spinner_class: string;
  search_button_class: string;
  path_nav_alert_class: string;
  file_view_alert_class: string;
  file_count_alert_class: string;
  contact_link: string;
  copyright_year: string;
  company_name: string;
  company_link: string;
  credit: boolean;
  display_size: boolean;
  display_time: boolean;
  display_download: boolean;
  disable_player: boolean;
  disable_video_download: boolean;
  allow_selecting_files: boolean;
  second_domain_for_dl: boolean;
  poster: string;
  audioposter: string;
  render_head_md: boolean;
  render_readme_md: boolean;
  unauthorized_owner_link: string;
  unauthorized_owner_email: string;
  downloaddomain: string;
  show_logout_button: boolean;
}

export interface PlayerConfig {
  player: 'videojs' | 'plyr' | 'dplayer' | 'jwplayer';
  videojs_version: string;
  plyr_io_version: string;
  jwplayer_version: string;
}

export interface AppConfig {
  environment: 'production' | 'development' | 'local';
  serviceaccounts: ServiceAccount[];
  domains_for_dl: string[];
  blocked_region: string[];
  blocked_asn: number[];
  auth: AuthConfig;
  ui: UIConfig;
  player: PlayerConfig;
  crypto_base_key: string;
  hmac_base_key: string;
  encrypt_iv: Uint8Array<ArrayBuffer>;
  download_mode: 'path' | 'id'; // New: path-based or ID-based downloads
  configBackend?: 'static' | 'd1' | 'hyperdrive'; // Backend selection
}

// ============================================================================
// Google Drive API Types
// ============================================================================

export interface DriveFile {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  createdTime?: string;
  fileExtension?: string;
  iconLink?: string;
  thumbnailLink?: string;
  driveId?: string;
  kind?: string;
  parents?: string[];
  link?: string; // Encrypted download link
}

export interface DriveListResponse {
  nextPageToken: string | null;
  curPageIndex: number;
  data: {
    files: DriveFile[];
    nextPageToken?: string;
  };
}

export interface DriveSearchResult {
  nextPageToken: string | null;
  curPageIndex: number;
  data: {
    files: DriveFile[];
  } | null;
}

export enum DriveRootType {
  USER_DRIVE = 0,
  SHARE_DRIVE = 1
}

// ============================================================================
// Request/Response Types
// ============================================================================

export interface ListRequestBody {
  id?: string;
  type?: string;
  password?: string;
  page_token?: string;
  page_index?: number;
}

export interface SearchRequestBody {
  q?: string;
  page_token?: string;
  page_index?: number;
}

export interface Id2PathRequestBody {
  id: string;
}

export interface LoginRequestBody {
  username: string;
  password: string;
}

export interface APIResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// ============================================================================
// Admin Panel Types
// ============================================================================

export interface AdminStats {
  totalDrives: number;
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  activeUsers: number;
  lastUpdated: string;
}

export interface AdminDriveInfo {
  index: number;
  name: string;
  id: string;
  type: DriveRootType;
  protected: boolean;
}

export interface AdminUser {
  username: string;
  createdAt?: string;
  lastLogin?: string;
  sessionCount?: number;
}

export interface AdminConfig {
  adminUsername: string;
  adminPassword: string;
  sessionSecret: string;
}

// ============================================================================
// Cache Types
// ============================================================================

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

export interface PathCache {
  [path: string]: string; // path -> id mapping
}

export interface FileCache {
  [path: string]: DriveFile;
}

export interface ChildrenCache {
  [path: string]: Array<{
    nextPageToken: string | null;
    data: { files: DriveFile[] };
  }>;
}

// ============================================================================
// Encrypted Data Types (for frontend)
// ============================================================================

export interface EncryptedFileData {
  id: string; // encrypted
  driveId: string; // encrypted
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  fileExtension?: string;
  link?: string; // encrypted download link
}

export interface FrontendModel {
  is_search_page: boolean;
  q?: string;
  root_type: DriveRootType;
}

// ============================================================================
// LocalStorage Types (for frontend caching)
// ============================================================================

export interface StoredFolder {
  id: string; // encrypted
  name: string;
  path: string;
  children?: string[]; // encrypted child IDs
  lastAccessed: number;
}

export interface StoredFile {
  id: string; // encrypted
  name: string;
  path: string;
  mimeType: string;
  size?: string;
  link?: string; // encrypted
  lastAccessed: number;
}

export interface LocalStorageCache {
  folders: { [path: string]: StoredFolder };
  files: { [path: string]: StoredFile };
  structure: { [folderId: string]: string[] }; // folder ID -> child IDs
  lastCleanup: number;
}

// ============================================================================
// Environment Bindings (Cloudflare Workers)
// ============================================================================

export interface Env {
  // Required Bindings
  ENV: KVNamespace;
  DB: D1Database;

  // Setup password (from wrangler.toml vars)
  SETUP_PASSWORD: string;
}

// ============================================================================
// Utility Types
// ============================================================================

export type FileType = 'video' | 'audio' | 'image' | 'code' | 'archive' | 'document' | 'markdown' | 'other';

export interface FileTypeConfig {
  video: string[];
  audio: string[];
  image: string[];
  code: string[];
  archive: string[];
  document: string[];
  markdown: string[];
}

export const FILE_TYPES: FileTypeConfig = {
  video: ['mp4', 'webm', 'avi', 'mpg', 'mpeg', 'mkv', 'rm', 'rmvb', 'mov', 'wmv', 'asf', 'ts', 'flv', '3gp', 'm4v'],
  audio: ['mp3', 'flac', 'wav', 'ogg', 'm4a', 'aac', 'wma', 'alac'],
  image: ['bmp', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'tiff', 'ico', 'webp'],
  code: ['php', 'css', 'go', 'java', 'js', 'json', 'txt', 'sh', 'md', 'html', 'xml', 'py', 'rb', 'c', 'cpp', 'h', 'hpp', 'ts', 'tsx', 'jsx', 'vue', 'svelte'],
  archive: ['zip', 'rar', 'tar', '7z', 'gz', 'bz2', 'xz'],
  document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp'],
  markdown: ['md', 'markdown']
};

export const FOLDER_MIME_TYPE = 'application/vnd.google-apps.folder';
export const DEFAULT_FILE_FIELDS = 'parents,id,name,mimeType,modifiedTime,createdTime,fileExtension,size';

// Re-export config backend types
export type { ConfigBackend } from './config-backend';
