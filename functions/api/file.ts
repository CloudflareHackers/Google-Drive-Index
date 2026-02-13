// GET /api/file?drive=0&id=fileId - Get single file metadata
import { getDrives, getConfig, getAdmin } from '../lib/db';
import { getFile } from '../lib/drive';
import { extractToken, verifyAuthToken } from '../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);

  try {
    const authEnabled = await getConfig(env.DB, 'auth_enabled');
    if (authEnabled === '1') {
      const admin = await getAdmin(env.DB);
      if (!admin) return Response.json({ error: 'Not configured' }, { status: 500 });
      const token = extractToken(request);
      if (!token) return Response.json({ error: 'Authentication required' }, { status: 401 });
      const result = await verifyAuthToken(token, admin.secret_key, url.hostname);
      if (!result.valid) return Response.json({ error: 'Invalid token' }, { status: 401 });
    }

    const driveIndex = parseInt(url.searchParams.get('drive') || '0');
    const fileId = url.searchParams.get('id');
    if (!fileId) return Response.json({ error: 'File ID required' }, { status: 400 });

    const drives = await getDrives(env.DB, true);
    if (driveIndex < 0 || driveIndex >= drives.length) {
      return Response.json({ error: 'Invalid drive' }, { status: 400 });
    }

    const file = await getFile(drives[driveIndex], fileId);
    return Response.json({ file });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 500 });
  }
};