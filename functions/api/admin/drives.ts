// /api/admin/drives - CRUD for drives
import { getDrives, getDrive, addDrive, updateDrive, deleteDrive } from '../../lib/db';
import { requireAdmin } from '../../lib/auth';

// GET - list all drives
export const onRequestGet: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const drives = await getDrives(context.env.DB);
  return Response.json({ drives });
};

// POST - add drive
export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const body: any = await context.request.json();
  if (!body.name || !body.client_id || !body.client_secret || !body.refresh_token) {
    return Response.json({ error: 'name, client_id, client_secret, and refresh_token are required' }, { status: 400 });
  }

  const id = await addDrive(context.env.DB, {
    name: body.name,
    client_id: body.client_id,
    client_secret: body.client_secret,
    refresh_token: body.refresh_token,
    root_folder_id: body.root_folder_id || 'root',
    is_shared_drive: body.is_shared_drive ? 1 : 0,
    enabled: body.enabled !== false ? 1 : 0,
    sort_order: body.sort_order || 0,
  });

  return Response.json({ success: true, id });
};

// PUT - update drive
export const onRequestPut: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const body: any = await context.request.json();
  if (!body.id) return Response.json({ error: 'id required' }, { status: 400 });

  await updateDrive(context.env.DB, body.id, body);
  return Response.json({ success: true });
};

// DELETE - delete drive
export const onRequestDelete: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const url = new URL(context.request.url);
  const id = parseInt(url.searchParams.get('id') || '');
  if (!id) return Response.json({ error: 'id required' }, { status: 400 });

  await deleteDrive(context.env.DB, id);
  return Response.json({ success: true });
};