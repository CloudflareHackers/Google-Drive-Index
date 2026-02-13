// POST /api/logout
export const onRequestPost: PagesFunction = async () => {
  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'auth_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    },
  });
};