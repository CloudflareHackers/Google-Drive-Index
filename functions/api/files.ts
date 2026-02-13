// GET /api/files?drive=1&folder=root&pageToken=xxx - List files
import { getDrives, getDrive, getConfig, getAdmin, isSetupComplete } from '../lib/db';
import { listFiles, getFile, isFolder } from '../lib/drive';
import { extractToken, verifyAuthToken } from '../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);

  try {
    // Check auth if enabled
    const authEnabled = await getConfig(env.DB, 'auth_enabled');
    if (authEnabled === '1') {
      const admin = await getAdmin(env.DB);
      if (!admin) return Response.json({ error: 'Not configured' }, { status: 500 });

      const token = extractToken(request);
      if (!token) return Response.json({ error: 'Authentication required' }, { status: 401 });

      const result = await verifyAuthToken(token, admin.secret_key, url.hostname);
      if (!result.valid) return Response.json({ error: 'Invalid token' }, { status: 401 });
    }

    const driveId = parseInt(url.searchParams.get('drive') || '0');
    const folderId = url.searchParams.get('folder') || 'root';
    const pageToken = url.searchParams.get('pageToken') || undefined;
    const pageSize = parseInt(url.searchParams.get('pageSize') || '50');

    // Get the drive config
    const drives = await getDrives(env.DB, true);
    if (driveId < 0 || driveId >= drives.length) {
      return Response.json({ error: 'Invalid drive index' }, { status: 400 });
    }

    const drive = drives[driveId];
    const result = await listFiles(drive, folderId, pageToken, pageSize);

    return Response.json({
      files: result.files.map(f => ({
        id: f.id,
        name: f.name,
        mimeType: f.mimeType,
        size: f.size,
        modifiedTime: f.modifiedTime,
        isFolder: isFolder(f.mimeType),
      })),
      nextPageToken: result.nextPageToken || null,
      drive: { id: drive.id, name: drive.name },
    });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 500 });
  }
};