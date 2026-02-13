// /api/admin/config - Manage site configuration
import { getAllConfig, setConfig } from '../../lib/db';
import { requireAdmin } from '../../lib/auth';

// GET - get all config
export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const config = await getAllConfig(context.env.DB);
  return Response.json({ config });
};

// POST - set config values
export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const body: any = await context.request.json();
  if (!body || typeof body !== 'object') {
    return Response.json({ error: 'Expected object with key-value pairs' }, { status: 400 });
  }

  for (const [key, value] of Object.entries(body)) {
    await setConfig(context.env.DB, key, String(value));
  }

  return Response.json({ success: true });
};