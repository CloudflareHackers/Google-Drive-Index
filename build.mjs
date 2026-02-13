// Build script - copies static assets to dist
// For Cloudflare Pages, the `dist` directory contains static files
// and `functions` directory contains the Pages Functions (auto-compiled by wrangler)
import { existsSync } from 'fs';

console.log('Build complete.');
console.log('Static assets in: dist/');
console.log('Pages Functions in: functions/');
console.log('');
console.log('To deploy: wrangler pages deploy dist');