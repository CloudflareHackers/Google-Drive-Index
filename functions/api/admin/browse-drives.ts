// POST /api/admin/browse-drives - Fetch available drives using a credential or SA
import { requireAdmin } from '../../lib/auth';

async function getAccessToken(db: D1Database, authType: string, credentialId: number): Promise<string> {
  if (authType === 'service_account') {
    const sa = await db.prepare('SELECT json_data FROM service_accounts WHERE id = ?').bind(credentialId).first<{json_data: string}>();
    if (!sa) throw new Error('Service account not found');
    const saJson = JSON.parse(sa.json_data);
    // Generate JWT for service account
    const iat = Math.floor(Date.now() / 1000);
    const header = btoa(JSON.stringify({alg:'RS256',typ:'JWT'})).replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g,'');
    const payload = btoa(JSON.stringify({iss:saJson.client_email,scope:'https://www.googleapis.com/auth/drive',aud:'https://oauth2.googleapis.com/token',exp:iat+3600,iat})).replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g,'');
    // Import private key
    const pemContent = saJson.private_key.split('\n').map((s:string)=>s.trim()).filter((l:string)=>l.length&&!l.startsWith('---')).join('');
    const binaryDer = Uint8Array.from(atob(pemContent), (c:string)=>c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', binaryDer.buffer, {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(header+'.'+payload));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g,'');
    const jwt = header+'.'+payload+'.'+sigB64;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion='+jwt
    });
    const tokenData: any = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('SA auth failed');
    return tokenData.access_token;
  }

  // OAuth credential
  const cred = await db.prepare('SELECT client_id, client_secret, refresh_token FROM credentials WHERE id = ?').bind(credentialId).first<{client_id:string;client_secret:string;refresh_token:string}>();
  if (!cred) throw new Error('Credential not found');
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body: new URLSearchParams({client_id:cred.client_id,client_secret:cred.client_secret,refresh_token:cred.refresh_token,grant_type:'refresh_token'}).toString()
  });
  const tokenData: any = await tokenRes.json();
  if (!tokenData.access_token) throw new Error('OAuth token refresh failed. Check credentials.');
  return tokenData.access_token;
}

export const onRequestPost: PagesFunction<{ DB: D1Database }> = async (context) => {
  const auth = await requireAdmin(context.request, context.env.DB);
  if (!auth.authenticated) return auth.response!;

  const body: any = await context.request.json();
  if (!body.credential_id) return Response.json({ error: 'Select a credential first' }, { status: 400 });

  try {
    const token = await getAccessToken(context.env.DB, body.auth_type || 'oauth', +body.credential_id);
    const drives: Array<{id:string;name:string;type:string}> = [];

    // Get personal root (only for OAuth, not SA)
    if (body.auth_type !== 'service_account') {
      try {
        const rootRes = await fetch('https://www.googleapis.com/drive/v3/files/root?fields=id,name', {
          headers: { Authorization: 'Bearer ' + token }
        });
        const rootData: any = await rootRes.json();
        if (rootData.id) drives.push({ id: rootData.id, name: rootData.name || 'My Drive', type: 'personal' });
      } catch {}
    }

    // Get all shared drives
    let pageToken: string | null = null;
    do {
      const url = 'https://www.googleapis.com/drive/v3/drives?pageSize=100&fields=nextPageToken,drives(id,name)' +
        (pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : '');
      const res = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
      const data: any = await res.json();
      if (data.error) return Response.json({ error: data.error.message || 'API error' }, { status: 400 });
      if (data.drives) {
        for (const d of data.drives) {
          drives.push({ id: d.id, name: d.name, type: 'shared' });
        }
      }
      pageToken = data.nextPageToken || null;
    } while (pageToken);

    return Response.json({ drives });
  } catch (e: any) {
    return Response.json({ error: e.message }, { status: 500 });
  }
};