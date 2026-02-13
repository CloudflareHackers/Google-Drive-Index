// POST /api/admin/password - Change admin password
import { getAdmin, createAdmin } from '../../lib/db';
import { requireAdmin, hashPassword, isStrongPassword, generateSecretKey } from '../../lib/auth';

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const body: any = await context.request.json();
  if (!body.current_password || !body.new_password) {
    return Response.json({ error: 'current_password and new_password required' }, { status: 400 });
  }

  const admin = await getAdmin(context.env.DB);
  if (!admin) return Response.json({ error: 'No admin' }, { status: 500 });

  // Verify current password
  const currentHash = await hashPassword(body.current_password, admin.secret_key);
  if (currentHash !== admin.password_hash) {
    return Response.json({ error: 'Current password is incorrect' }, { status: 401 });
  }

  // Validate new password
  const strength = isStrongPassword(body.new_password);
  if (!strength.valid) {
    return Response.json({ error: strength.message }, { status: 400 });
  }

  // Generate new secret key and hash
  const newSecretKey = generateSecretKey();
  const newHash = await hashPassword(body.new_password, newSecretKey);
  await createAdmin(context.env.DB, admin.username, newHash, newSecretKey);

  return Response.json({ success: true, message: 'Password changed. Please log in again.' });
};