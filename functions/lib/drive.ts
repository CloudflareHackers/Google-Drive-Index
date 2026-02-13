// Google Drive API helpers

import type { DriveConfig } from './db';

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface DriveFile {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  description?: string;
  iconLink?: string;
  thumbnailLink?: string;
  shortcutDetails?: {
    targetId: string;
    targetMimeType: string;
  };
}

interface DriveListResponse {
  files: DriveFile[];
  nextPageToken?: string;
}

// Token cache (in-memory per isolate)
const tokenCache = new Map<number, { token: string; expires: number }>();

// Get access token for a drive
async function getAccessToken(drive: DriveConfig): Promise<string> {
  const cached = tokenCache.get(drive.id);
  if (cached && cached.expires > Date.now()) {
    return cached.token;
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: drive.client_id,
      client_secret: drive.client_secret,
      refresh_token: drive.refresh_token,
      grant_type: 'refresh_token',
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get access token: ${error}`);
  }

  const data: TokenResponse = await response.json();
  tokenCache.set(drive.id, {
    token: data.access_token,
    expires: Date.now() + (data.expires_in - 60) * 1000,
  });

  return data.access_token;
}

// List files in a folder
export async function listFiles(
  drive: DriveConfig,
  folderId: string = 'root',
  pageToken?: string,
  pageSize: number = 50,
  orderBy: string = 'folder,name'
): Promise<{ files: DriveFile[]; nextPageToken?: string }> {
  const token = await getAccessToken(drive);
  const actualFolderId = folderId === 'root' ? drive.root_folder_id : folderId;

  const params = new URLSearchParams({
    q: `'${actualFolderId}' in parents and trashed = false`,
    fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, description, iconLink, thumbnailLink, shortcutDetails)',
    pageSize: String(pageSize),
    orderBy,
    supportsAllDrives: 'true',
    includeItemsFromAllDrives: 'true',
  });

  if (pageToken) params.set('pageToken', pageToken);
  if (drive.is_shared_drive) {
    params.set('driveId', drive.root_folder_id);
    params.set('corpora', 'drive');
  }

  const response = await fetch(`https://www.googleapis.com/drive/v3/files?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Drive API error: ${error}`);
  }

  return await response.json();
}

// Get file metadata
export async function getFile(drive: DriveConfig, fileId: string): Promise<DriveFile> {
  const token = await getAccessToken(drive);

  const params = new URLSearchParams({
    fields: 'id, name, mimeType, size, modifiedTime, description, iconLink, thumbnailLink, shortcutDetails',
    supportsAllDrives: 'true',
  });

  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Drive API error: ${error}`);
  }

  return await response.json();
}

// Search files across a drive
export async function searchFiles(
  drive: DriveConfig,
  query: string,
  pageToken?: string,
  pageSize: number = 50
): Promise<{ files: DriveFile[]; nextPageToken?: string }> {
  const token = await getAccessToken(drive);

  const escapedQuery = query.replace(/'/g, "\\'");
  const params = new URLSearchParams({
    q: `name contains '${escapedQuery}' and trashed = false`,
    fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, description, iconLink, thumbnailLink)',
    pageSize: String(pageSize),
    supportsAllDrives: 'true',
    includeItemsFromAllDrives: 'true',
  });

  if (pageToken) params.set('pageToken', pageToken);
  if (drive.is_shared_drive) {
    params.set('driveId', drive.root_folder_id);
    params.set('corpora', 'drive');
  }

  const response = await fetch(`https://www.googleapis.com/drive/v3/files?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Drive API error: ${error}`);
  }

  return await response.json();
}

// Get file download stream
export async function getFileStream(drive: DriveConfig, fileId: string): Promise<Response> {
  const token = await getAccessToken(drive);

  const params = new URLSearchParams({
    alt: 'media',
    supportsAllDrives: 'true',
  });

  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  return response;
}

// Export Google Docs (Sheets, Docs, Slides, etc.)
export async function exportFile(drive: DriveConfig, fileId: string, mimeType: string): Promise<Response> {
  const token = await getAccessToken(drive);

  const params = new URLSearchParams({ mimeType });

  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/export?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  return response;
}

// MIME type helpers
export function isFolder(mimeType: string): boolean {
  return mimeType === 'application/vnd.google-apps.folder';
}

export function isGoogleDoc(mimeType: string): boolean {
  return mimeType.startsWith('application/vnd.google-apps.');
}

export function getExportMimeType(mimeType: string): string | null {
  const map: Record<string, string> = {
    'application/vnd.google-apps.document': 'application/pdf',
    'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.google-apps.presentation': 'application/pdf',
    'application/vnd.google-apps.drawing': 'image/png',
    'application/vnd.google-apps.script': 'application/vnd.google-apps.script+json',
  };
  return map[mimeType] || null;
}

export function getFileIcon(mimeType: string): string {
  if (isFolder(mimeType)) return '📁';
  if (mimeType.startsWith('image/')) return '🖼️';
  if (mimeType.startsWith('video/')) return '🎬';
  if (mimeType.startsWith('audio/')) return '🎵';
  if (mimeType === 'application/pdf') return '📄';
  if (mimeType.includes('zip') || mimeType.includes('compressed') || mimeType.includes('archive')) return '📦';
  if (mimeType.includes('document') || mimeType.includes('text')) return '📝';
  if (mimeType.includes('spreadsheet') || mimeType.includes('excel')) return '📊';
  if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) return '📽️';
  return '📄';
}

export function formatFileSize(bytes: string | undefined): string {
  if (!bytes) return '-';
  const size = parseInt(bytes);
  if (isNaN(size)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let s = size;
  while (s >= 1024 && i < units.length - 1) {
    s /= 1024;
    i++;
  }
  return `${s.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}