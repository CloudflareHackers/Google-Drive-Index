// Authentication helpers

import { getAdmin, isSetupComplete, type Env } from './db';

// Hash password using SHA-256
export async function hashPassword(password: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate a random secret key
export function generateSecretKey(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Create auth token: base64(JSON({ username, domain, ts })) signed with HMAC
export async function createAuthToken(username: string, domain: string, secretKey: string): Promise<string> {
  const payload = JSON.stringify({ u: username, d: domain, t: Date.now() });
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secretKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

  const token = btoa(JSON.stringify({ p: payload, s: sigHex }));
  return token;
}

// Verify auth token
export async function verifyAuthToken(token: string, secretKey: string, domain: string): Promise<{ valid: boolean; username?: string }> {
  try {
    const decoded = JSON.parse(atob(token));
    const { p: payload, s: sigHex } = decoded;
    const parsedPayload = JSON.parse(payload);

    // Check domain
    if (parsedPayload.d !== domain) {
      return { valid: false };
    }

    // Check token age (24 hours)
    const age = Date.now() - parsedPayload.t;
    if (age > 24 * 60 * 60 * 1000) {
      return { valid: false };
    }

    // Verify HMAC
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secretKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['verify']
    );

    const sigBytes = new Uint8Array(sigHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(payload));

    return { valid, username: valid ? parsedPayload.u : undefined };
  } catch {
    return { valid: false };
  }
}

// Validate password strength
export function isStrongPassword(password: string): { valid: boolean; message: string } {
  if (password.length < 8) return { valid: false, message: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { valid: false, message: 'Password must contain an uppercase letter' };
  if (!/[a-z]/.test(password)) return { valid: false, message: 'Password must contain a lowercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, message: 'Password must contain a number' };
  if (!/[^A-Za-z0-9]/.test(password)) return { valid: false, message: 'Password must contain a special character' };
  return { valid: true, message: 'Password is strong' };
}

// Extract auth token from request (cookie or header)
export function extractToken(request: Request): string | null {
  // Check Authorization header first
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // Check cookie
  const cookie = request.headers.get('Cookie');
  if (cookie) {
    const match = cookie.match(/auth_token=([^;]+)/);
    if (match) return match[1];
  }

  return null;
}

// Middleware: check if request is authenticated for admin
export async function requireAdmin(request: Request, db: D1Database): Promise<{ authenticated: boolean; username?: string; response?: Response }> {
  const setupComplete = await isSetupComplete(db);
  if (!setupComplete) {
    return { authenticated: false, response: Response.json({ error: 'Setup not complete', redirect: '/' }, { status: 403 }) };
  }

  const admin = await getAdmin(db);
  if (!admin) {
    return { authenticated: false, response: Response.json({ error: 'No admin configured' }, { status: 403 }) };
  }

  const token = extractToken(request);
  if (!token) {
    return { authenticated: false, response: Response.json({ error: 'Authentication required', redirect: '/login/' }, { status: 401 }) };
  }

  const url = new URL(request.url);
  const result = await verifyAuthToken(token, admin.secret_key, url.hostname);
  if (!result.valid) {
    return { authenticated: false, response: Response.json({ error: 'Invalid or expired token', redirect: '/login/' }, { status: 401 }) };
  }

  return { authenticated: true, username: result.username };
}