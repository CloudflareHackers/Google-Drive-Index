// POST /api/setup - First-time setup: create admin account
import { isSetupComplete, createAdmin } from '../lib/db';
import { hashPassword, generateSecretKey, isStrongPassword } from '../lib/auth';

interface SetupRequest {
  username: string;
  password: string;
}

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const { request, env } = context;

  try {
    // Check if already set up
    const complete = await isSetupComplete(env.DB);
    if (complete) {
      return Response.json({ error: 'Setup already completed' }, { status: 400 });
    }

    const body: SetupRequest = await request.json();

    // Validate input
    if (!body.username || body.username.length < 3) {
      return Response.json({ error: 'Username must be at least 3 characters' }, { status: 400 });
    }

    if (!body.password) {
      return Response.json({ error: 'Password is required' }, { status: 400 });
    }

    const strength = isStrongPassword(body.password);
    if (!strength.valid) {
      return Response.json({ error: strength.message }, { status: 400 });
    }

    // Generate secret key and hash password
    const secretKey = generateSecretKey();
    const passwordHash = await hashPassword(body.password, secretKey);

    // Create admin
    await createAdmin(env.DB, body.username, passwordHash, secretKey);

    return Response.json({ success: true, message: 'Admin account created. Please log in.' });
  } catch (err: any) {
    return Response.json({ error: err.message || 'Setup failed' }, { status: 500 });
  }
};
