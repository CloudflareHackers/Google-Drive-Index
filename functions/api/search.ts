// GET /api/search?q=query&drive=0&pageToken=xxx - Search files
import { getDrives, getConfig, getAdmin } from '../lib/db';
import { searchFiles, isFolder } from '../lib/drive';
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

    const allowSearch = await getConfig(env.DB, 'allow_search');
    if (allowSearch === '0') {
      return Response.json({ error: 'Search is disabled' }, { status: 403 });
    }

    const query = url.searchParams.get('q') || '';
    if (!query || query.length < 2) {
      return Response.json({ error: 'Query must be at least 2 characters' }, { status: 400 });
    }

    const driveIndex = url.searchParams.get('drive');
    const pageToken = url.searchParams.get('pageToken') || undefined;
    const drives = await getDrives(env.DB, true);

    if (drives.length === 0) {
      return Response.json({ results: [], nextPageToken: null });
    }

    // Search specific drive or all drives
    if (driveIndex !== null && driveIndex !== undefined) {
      const idx = parseInt(driveIndex);
      if (idx >= 0 && idx < drives.length) {
        const result = await searchFiles(drives[idx], query, pageToken);
        return Response.json({
          results: result.files.map(f => ({
            id: f.id,
            name: f.name,
            mimeType: f.mimeType,
            size: f.size,
            modifiedTime: f.modifiedTime,
            isFolder: isFolder(f.mimeType),
            driveIndex: idx,
            driveName: drives[idx].name,
          })),
          nextPageToken: result.nextPageToken || null,
        });
      }
    }

    // Search all drives
    const allResults: any[] = [];
    for (let i = 0; i < drives.length; i++) {
      try {
        const result = await searchFiles(drives[i], query);
        for (const f of result.files) {
          allResults.push({
            id: f.id,
            name: f.name,
            mimeType: f.mimeType,
            size: f.size,
            modifiedTime: f.modifiedTime,
            isFolder: isFolder(f.mimeType),
            driveIndex: i,
            driveName: drives[i].name,
          });
        }
      } catch {
        // Skip drives that fail
      }
    }

    return Response.json({ results: allResults, nextPageToken: null });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 500 });
  }
};