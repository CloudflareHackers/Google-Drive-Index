/**
 * Google Drive Index - Cloudflare Worker Entry Point
 * @version 3.0.0
 */

import { handleRequest } from './router';
import type { Env } from './types';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error('Worker error:', error);
      return new Response(`Internal Server Error: ${(error as Error).message}`, {
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }
};

// Legacy addEventListener support
addEventListener('fetch', (event: FetchEvent) => {
  event.respondWith(
    handleRequest(event.request, {} as any).catch(
      err => new Response(`Error: ${err.stack}`, { status: 500 })
    )
  );
});
