// /api/admin/credentials - OAuth credentials CRUD
import { requireAdmin } from '../../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const rows = await context.env.DB.prepare('SELECT id, name, created_at FROM credentials ORDER BY id').all();
  return Response.json({ credentials: rows.results || [] });
};

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const body: any = await context.request.json();
  if (!body.name || !body.client_id || !body.client_secret || !body.refresh_token) {
    return Response.json({ error: 'name, client_id, client_secret, refresh_token required' }, { status: 400 });
  }
  await context.env.DB.prepare(
    'INSERT INTO credentials (name, client_id, client_secret, refresh_token) VALUES (?, ?, ?, ?)'
  ).bind(body.name, body.client_id, body.client_secret, body.refresh_token).run();
  return Response.json({ success: true });
};

export const onRequestDelete: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const url = new URL(context.request.url);
  const id = url.searchParams.get('id');
  if (!id) return Response.json({ error: 'id required' }, { status: 400 });
  // Check if used by drives
  const usage = await context.env.DB.prepare("SELECT COUNT(*) as cnt FROM drives WHERE credential_id = ?").bind(id).first<{cnt:number}>();
  if (usage && usage.cnt > 0) return Response.json({ error: usage.cnt + ' drive(s) use this credential' }, { status: 400 });
  await context.env.DB.prepare('DELETE FROM credentials WHERE id = ?').bind(id).run();
  return Response.json({ success: true });
};