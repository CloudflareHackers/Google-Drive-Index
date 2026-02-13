// /download/:driveIndex/:fileId - Download files
import { getDrives, getConfig, getAdmin } from '../lib/db';
import { getFile, getFileStream, isGoogleDoc, getExportMimeType, exportFile } from '../lib/drive';
import { extractToken, verifyAuthToken } from '../lib/auth';

export const onRequest: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env, params } = context;
  const url = new URL(request.url);

  try {
    // Parse path: /download/{driveIndex}/{fileId}
    const pathParts = (params.path as string[]) || [];
    if (pathParts.length < 2) {
      return new Response('Usage: /download/{driveIndex}/{fileId}', { status: 400 });
    }

    const driveIndex = parseInt(pathParts[0]);
    const fileId = pathParts[1];

    // Check auth if needed
    const authEnabled = await getConfig(env.DB, 'auth_enabled');
    if (authEnabled === '1') {
      const admin = await getAdmin(env.DB);
      if (!admin) return new Response('Not configured', { status: 500 });
      const token = extractToken(request);
      if (!token) return new Response('Authentication required', { status: 401 });
      const result = await verifyAuthToken(token, admin.secret_key, url.hostname);
      if (!result.valid) return new Response('Invalid token', { status: 401 });
    }

    // Check download permission
    const allowDownload = await getConfig(env.DB, 'allow_download');
    if (allowDownload === '0') {
      return new Response('Downloads are disabled', { status: 403 });
    }

    const drives = await getDrives(env.DB, true);
    if (driveIndex < 0 || driveIndex >= drives.length) {
      return new Response('Invalid drive', { status: 400 });
    }

    const drive = drives[driveIndex];

    // Get file metadata
    const file = await getFile(drive, fileId);
    if (!file || !file.name) {
      return new Response('File not found', { status: 404 });
    }

    // Handle Google Docs export
    if (isGoogleDoc(file.mimeType)) {
      const exportMime = getExportMimeType(file.mimeType);
      if (!exportMime) {
        return new Response('This file type cannot be downloaded', { status: 400 });
      }
      const exportResp = await exportFile(drive, fileId, exportMime);
      if (!exportResp.ok) {
        return new Response('Export failed', { status: exportResp.status });
      }
      const headers = new Headers(exportResp.headers);
      headers.set('Content-Disposition', `attachment; filename="${file.name}"`);
      return new Response(exportResp.body, { status: 200, headers });
    }

    // Stream the file
    const range = request.headers.get('Range') || '';
    const inline = url.searchParams.get('inline') === 'true';

    const resp = await getFileStream(drive, fileId);
    if (!resp.ok) {
      return new Response('Download failed', { status: resp.status });
    }

    const headers = new Headers();
    headers.set('Content-Type', resp.headers.get('Content-Type') || 'application/octet-stream');
    if (file.size) headers.set('Content-Length', file.size);
    headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename="${file.name}"`);
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Cache-Control', 'public, max-age=3600');

    // Forward content range headers if present
    const contentRange = resp.headers.get('Content-Range');
    if (contentRange) headers.set('Content-Range', contentRange);

    return new Response(resp.body, {
      status: resp.status,
      headers,
    });
  } catch (err: any) {
    return new Response(`Download error: ${err.message}`, { status: 500 });
  }
};