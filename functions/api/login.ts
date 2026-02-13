// POST /api/login - Admin login
import { getAdmin, isSetupComplete } from '../lib/db';
import { hashPassword, createAuthToken } from '../lib/auth';

interface LoginRequest {
  username: string;
  password: string;
}

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env } = context;

  try {
    const complete = await isSetupComplete(env.DB);
    if (!complete) {
      return Response.json({ error: 'Setup not complete', redirect: '/' }, { status: 403 });
    }

    const body: LoginRequest = await request.json();
    if (!body.username || !body.password) {
      return Response.json({ error: 'Username and password required' }, { status: 400 });
    }

    const admin = await getAdmin(env.DB);
    if (!admin) {
      return Response.json({ error: 'No admin configured' }, { status: 500 });
    }

    const passwordHash = await hashPassword(body.password, admin.secret_key);
    if (passwordHash !== admin.password_hash || body.username !== admin.username) {
      return Response.json({ error: 'Invalid credentials' }, { status: 401 });
    }

    const url = new URL(request.url);
    const token = await createAuthToken(admin.username, url.hostname, admin.secret_key);

    return new Response(JSON.stringify({ success: true, token }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `auth_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      },
    });
  } catch (err: any) {
    return Response.json({ error: err.message || 'Login failed' }, { status: 500 });
  }
};