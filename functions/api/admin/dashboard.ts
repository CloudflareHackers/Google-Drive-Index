// GET /api/admin/dashboard - Dashboard stats
import { requireAdmin } from '../../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const db = context.env.DB;
  const [drives, creds, sa, config, driveList] = await Promise.all([
    db.prepare('SELECT COUNT(*) as cnt FROM drives').first<{cnt:number}>(),
    db.prepare('SELECT COUNT(*) as cnt FROM credentials').first<{cnt:number}>().catch(() => ({cnt:0})),
    db.prepare('SELECT COUNT(*) as cnt FROM service_accounts').first<{cnt:number}>().catch(() => ({cnt:0})),
    db.prepare('SELECT COUNT(*) as cnt FROM config').first<{cnt:number}>(),
    db.prepare('SELECT d.name, d.root_folder_id, d.auth_type, d.credential_id, COALESCE(c.name, sa.name, "") as auth_name FROM drives d LEFT JOIN credentials c ON d.auth_type="oauth" AND d.credential_id=c.id LEFT JOIN service_accounts sa ON d.auth_type="service_account" AND d.credential_id=sa.id ORDER BY d.sort_order').all().catch(() => ({results:[]})),
  ]);

  const siteName = await db.prepare("SELECT value FROM config WHERE key='site_name'").first<{value:string}>();

  return Response.json({
    counts: {
      drives: drives?.cnt || 0,
      credentials: creds?.cnt || 0,
      service_accounts: sa?.cnt || 0,
      config: config?.cnt || 0,
    },
    site_name: siteName?.value || 'Google Drive Index',
    drives: driveList.results || [],
  });
};