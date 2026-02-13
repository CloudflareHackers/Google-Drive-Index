// GET /api/status - Check setup status and auth status
import { isSetupComplete, getAdmin, getAllConfig, getDrives } from '../lib/db';
import { extractToken, verifyAuthToken } from '../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env } = context;

  try {
    const setupComplete = await isSetupComplete(env.DB);

    if (!setupComplete) {
      return Response.json({ setup_complete: false, authenticated: false });
    }

    const admin = await getAdmin(env.DB);
    if (!admin) {
      return Response.json({ setup_complete: false, authenticated: false });
    }

    // Check auth
    const token = extractToken(request);
    let authenticated = false;
    let username: string | undefined;

    if (token) {
      const url = new URL(request.url);
      const result = await verifyAuthToken(token, admin.secret_key, url.hostname);
      authenticated = result.valid;
      username = result.username;
    }

    const config = await getAllConfig(env.DB);
    const drives = await getDrives(env.DB, true);

    return Response.json({
      setup_complete: true,
      authenticated,
      username,
      config: {
        site_name: config.site_name || 'Google Drive Index',
        theme: config.theme || 'dark',
        allow_search: config.allow_search !== '0',
        allow_download: config.allow_download !== '0',
        auth_enabled: config.auth_enabled === '1',
      },
      drives: drives.map(d => ({ id: d.id, name: d.name })),
    });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 500 });
  }
};