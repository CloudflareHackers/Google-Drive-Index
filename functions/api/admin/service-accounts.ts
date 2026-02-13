// /api/admin/service-accounts - Service accounts CRUD
import { requireAdmin } from '../../lib/auth';

export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const rows = await context.env.DB.prepare('SELECT id, name, enabled, created_at FROM service_accounts ORDER BY id').all();
  return Response.json({ accounts: rows.results || [] });
};

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const body: any = await context.request.json();
  if (!body.json_data) return Response.json({ error: 'json_data required' }, { status: 400 });
  try {
    const sa = JSON.parse(body.json_data);
    if (!sa.client_email) return Response.json({ error: 'Invalid SA JSON: missing client_email' }, { status: 400 });
    await context.env.DB.prepare(
      'INSERT INTO service_accounts (name, json_data, enabled) VALUES (?, ?, 1)'
    ).bind(sa.client_email, body.json_data).run();
    return Response.json({ success: true });
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }
};

export const onRequestDelete: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;
  const url = new URL(context.request.url);
  const id = url.searchParams.get('id');
  if (!id) return Response.json({ error: 'id required' }, { status: 400 });
  const usage = await context.env.DB.prepare("SELECT COUNT(*) as cnt FROM drives WHERE auth_type='service_account' AND credential_id = ?").bind(id).first<{cnt:number}>();
  if (usage && usage.cnt > 0) return Response.json({ error: usage.cnt + ' drive(s) use this SA' }, { status: 400 });
  await context.env.DB.prepare('DELETE FROM service_accounts WHERE id = ?').bind(id).run();
  return Response.json({ success: true });
};