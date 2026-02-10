# Google Drive Index v3.0

**🌐 Live Demo:** [https://google-drive-index.1337-files.workers.dev](https://google-drive-index.1337-files.workers.dev)

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-100%25-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Modern, TypeScript-based Google Drive Index on Cloudflare Workers**

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/CloudflareHackers/Google-Drive-Index)

[Features](#-features) • [Quick Start](#-quick-start) • [Deploy](#-deployment-options) • [Docs](#-documentation)

</div>

---

## 🎯 One-Click Deploy

### Deploy to Cloudflare Workers

1. Click the button above ☝️
2. Connect your GitHub account
3. Enter your Google Drive folder ID
4. Click "Deploy"
5. Done! Your index is live 🎉

**Or follow the detailed guides:**
- [GitHub Actions Setup](./GITHUB-DEPLOY.md) - Automatic deployment from GitHub
- [Manual Deployment](./DEPLOY.md) - Deploy using Wrangler CLI

---

## 🌟 Features

### Core Features
- ✅ **3 Configuration Backends** - Static, D1 Database, or External DB via HyperDrive
- ✅ **WordPress-Style Setup** - 5-step wizard for easy configuration
- ✅ **Dynamic Configuration** - Change settings without redeployment (D1/HyperDrive)
- ✅ **Admin Panel** - Full-featured management interface at `/admin`
- ✅ **TypeScript** - 100% type-safe codebase
- ✅ **Multi-Drive Support** - Index multiple Google Drives simultaneously
- ✅ **Advanced Search** - Search across all your drives
- ✅ **Dual Download Modes** - Path-based or ID-based downloads

### Security & Performance
- 🔐 **AES-256 Encryption** - Secure file ID encryption
- 🔐 **HMAC Integrity** - Tamper-proof download links
- 🔐 **Time-Limited Links** - Auto-expiring download URLs
- 🔐 **IP Locking** - Optional IP-based access control
- ⚡ **Edge Computing** - Deploy on Cloudflare's global network
- ⚡ **Smart Caching** - 5-minute config cache, localStorage support
- ⚡ **No External CDN** - All assets served from worker

### User Experience
- 🎨 **20+ Themes** - Bootswatch theme support
- 🎨 **Responsive Design** - Works on all devices
- 📱 **Mobile Optimized** - Touch-friendly interface
- 🎬 **Media Players** - Built-in video/audio players (VideoJS, Plyr, DPlayer, JWPlayer)
- 📄 **Markdown Support** - Render README.md and HEAD.md
- 🔍 **File ID Lookup** - Find files by ID across all drives

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Cloudflare Workers account (free tier available)
- Google Drive API credentials

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/google-drive-index.git
cd google-drive-index
npm install
```

### 2. Choose Your Configuration Backend

<details>
<summary><b>Option A: Static Configuration (Simplest)</b></summary>

**Best for:** Personal use, simple setups

```bash
# 1. Edit src/config.ts
# Add your Google Drive folder IDs and settings

# 2. Deploy
npm run deploy

# Done! ✓
```

**Pros:** Simple, fast, no database needed  
**Cons:** Requires redeployment for changes

</details>

<details>
<summary><b>Option B: D1 Database (Recommended)</b></summary>

**Best for:** Dynamic configuration, multiple admins

```bash
# 1. Create D1 database
wrangler d1 create google-drive-index-db

# 2. Copy the database_id from output
# Update wrangler.toml:
[[d1_databases]]
binding = "DB"
database_name = "google-drive-index-db"
database_id = "YOUR_DATABASE_ID_HERE"

# 3. Set backend in src/config.ts
configBackend: 'd1'

# 4. Deploy
npm run deploy

# 5. Visit https://your-worker.workers.dev/setup
# Complete the 5-step setup wizard

# Done! ✓
```

**Pros:** Dynamic config, admin panel, no external DB  
**Cons:** Cloudflare-specific

</details>

<details>
<summary><b>Option C: HyperDrive (Enterprise)</b></summary>

**Best for:** Existing database infrastructure, advanced features

```bash
# 1. Create HyperDrive connection
wrangler hyperdrive create gdi-db --connection-string="postgresql://user:pass@host:5432/db"

# 2. Copy the hyperdrive_id from output
# Update wrangler.toml:
[[hyperdrive]]
binding = "HYPERDRIVE"
id = "YOUR_HYPERDRIVE_ID_HERE"

# 3. Set backend in src/config.ts
configBackend: 'hyperdrive'

# 4. Deploy
npm run deploy

# 5. Visit https://your-worker.workers.dev/setup
# Complete the setup wizard

# Done! ✓
```

**Pros:** Use existing DB, advanced features, backup tools  
**Cons:** External dependency, connection overhead

</details>

---

## 📦 Deployment Options

### Method 1: Manual Deployment (Wrangler CLI)

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Deploy
npm run deploy
```

### Method 2: GitHub Actions (Automated) ⭐ **NEW**

**One-time setup:**

1. **Get Cloudflare API Token:**
   - Go to https://dash.cloudflare.com/profile/api-tokens
   - Create Token → Use template "Edit Cloudflare Workers"
   - Copy the token

2. **Get Account ID:**
   - Go to Workers & Pages
   - Copy your Account ID from the right sidebar

3. **Add to GitHub Secrets:**
   - Go to your repo → Settings → Secrets and variables → Actions
   - Add secrets:
     - `CLOUDFLARE_API_TOKEN` = your API token
     - `CLOUDFLARE_ACCOUNT_ID` = your account ID

4. **Push to main branch:**
```bash
git add .
git commit -m "Deploy"
git push origin main
```

Your worker will automatically deploy! 🎉

**Manual trigger:**
- Go to Actions tab → Deploy to Cloudflare Workers → Run workflow

---

## ⚙️ Configuration

### Basic Configuration (src/config.ts)

```typescript
export const config: AppConfig = {
  // Choose backend: 'static' | 'd1' | 'hyperdrive'
  configBackend: 'static',
  
  // Environment
  environment: 'production',
  
  // Download mode: 'path' or 'id'
  download_mode: 'path',
  
  // Google Drive roots
  auth: {
    siteName: 'My Drive Index',
    roots: [
      {
        id: 'YOUR_FOLDER_ID', // or 'root' for My Drive
        name: 'My Drive',
        protect_file_link: false
      }
    ],
    
    // OAuth2 credentials (for user account)
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    refresh_token: 'YOUR_REFRESH_TOKEN',
    
    // Or use service account
    service_account: true,
    // Add service account JSON to serviceaccounts array
  }
};
```

### Generate Encryption Keys

**Important:** Generate your own keys for security!

```javascript
// Run in Node.js or browser console
const crypto = require('crypto');

console.log('crypto_base_key:', crypto.randomBytes(32).toString('hex'));
console.log('hmac_base_key:', crypto.randomBytes(32).toString('hex'));
console.log('encrypt_iv:', JSON.stringify(Array.from(crypto.randomBytes(16))));
```

Update in `src/config.ts`:
```typescript
const CRYPTO_BASE_KEY = 'your_generated_key';
const HMAC_BASE_KEY = 'your_generated_key';
const ENCRYPT_IV = new Uint8Array([...]); // your generated IV
```

### Get Google Drive Credentials

<details>
<summary><b>Option 1: OAuth2 (User Account)</b></summary>

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Google Drive API
4. Create OAuth 2.0 credentials
5. Use [OAuth Playground](https://developers.google.com/oauthplayground/) to get refresh token
6. Add to `src/config.ts`

</details>

<details>
<summary><b>Option 2: Service Account (Recommended)</b></summary>

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Google Drive API
4. Create Service Account
5. Download JSON key
6. Share your Google Drive folders with service account email
7. Add JSON to `serviceaccounts` array in `src/config.ts`

</details>

---

## 🎨 Customization

### Themes

Choose from 20+ Bootswatch themes:

```typescript
ui: {
  theme: 'darkly', // or: cerulean, cosmo, cyborg, flatly, journal, 
                   // litera, lumen, lux, materia, minty, morph, pulse,
                   // quartz, sandstone, simplex, sketchy, slate, solar,
                   // spacelab, superhero, united, vapor, yeti, zephyr
}
```

Preview themes: https://bootswatch.com/

### Colors

```typescript
ui: {
  css_a_tag_color: 'white',
  css_p_tag_color: 'white',
  folder_text_color: 'white',
  header_style_class: 'navbar-dark bg-primary',
  footer_style_class: 'bg-primary',
}
```

### Video Players

```typescript
player: {
  player: 'videojs', // or: plyr, dplayer, jwplayer
  videojs_version: '8.3.0'
}
```

---

## 🛠️ Admin Panel

Access at `/admin` (default credentials: `admin` / `changeme123`)

### Features

- **Dashboard** - System statistics and overview
- **Configuration** - Manage all settings (D1/HyperDrive only)
- **Drives** - Add/edit/remove Google Drive roots
- **Users** - Manage user accounts (if login enabled)
- **Service Accounts** - Rotate service account credentials
- **Cache** - Clear configuration cache
- **Quick Actions** - Common administrative tasks

### Changing Admin Password

```typescript
// src/config.ts
export const adminConfig = {
  enabled: true,
  username: 'admin',
  password: 'YOUR_SECURE_PASSWORD', // Change this!
  sessionSecret: 'YOUR_SESSION_SECRET', // Change this!
  sessionDuration: 24 * 60 * 60 * 1000 // 24 hours
};
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [PROJECT-SUMMARY.md](./PROJECT-SUMMARY.md) | Complete project overview |
| [MULTI-BACKEND.md](./MULTI-BACKEND.md) | Backend configuration guide |
| [CONFIG-OPTIONS.md](./CONFIG-OPTIONS.md) | All configuration options |
| [GITHUB-DEPLOY.md](./GITHUB-DEPLOY.md) | GitHub Actions deployment guide ⭐ |
| [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | Fix common issues ⭐ |
| [MIGRATION.md](./MIGRATION.md) | Upgrade from v2.x guide |
| [DEPLOY.md](./DEPLOY.md) | Detailed deployment instructions |
| [QUICK-REF.md](./QUICK-REF.md) | Quick reference card |

---

## 🔧 Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Type checking
npm run typecheck

# Lint code
npm run lint

# Format code
npm run format

# Deploy to production
npm run deploy
```

---

## 📊 Project Statistics

- **TypeScript Files:** 19
- **Total Lines:** 5,500+
- **Functions:** 50+
- **Backends:** 3
- **Database Tables:** 7
- **Setup Steps:** 5
- **Documentation Files:** 7+

---

## 🔗 API Integration

### Open File/Folder by Google Drive ID

Use the `/findpath` endpoint to open any file or folder by its Google Drive ID. This endpoint searches across ALL configured drives to find the file.

```
GET /findpath?id={GOOGLE_DRIVE_FILE_ID}&view=true
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | Yes | Google Drive file or folder ID |
| `view` | No | Set to `true` to open in view/preview mode |

**Example:**
```
https://google-drive-index.1337-files.workers.dev/findpath?id=1j51RKs0AZzft8WhBbQTAN_a3l74So4FJ&view=true
```

**How it works:**
1. Tries each configured drive to resolve the file ID to a folder path
2. If found → 302 redirect to `/{driveIndex}:/path/to/file?a=view`
3. If not found in any drive → Falls back to ID-based access at `/fallback?id={encryptedId}`

**Use cases:**
- External apps linking to files by Google Drive ID
- Telegram bots, web apps, or other services that know file IDs
- Cross-drive file resolution (file in Drive 1 accessible via Drive 0's endpoint)

---

## 🗺️ Roadmap

- [ ] MongoDB support
- [ ] Multi-language support
- [ ] Advanced file preview
- [ ] Bulk operations
- [ ] API key management
- [ ] Webhook support
- [ ] Activity logs
- [ ] File sharing links

---

## 🐛 Troubleshooting

### Setup wizard not appearing
- Check `configBackend` setting in `src/config.ts`
- Verify database bindings in `wrangler.toml`
- Check `setup_state` table exists

### Database connection errors
- Verify binding names match in `wrangler.toml`
- Check database credentials
- Review Cloudflare dashboard logs

### Downloads not working
- Verify encryption keys are set
- Check file permissions in Google Drive
- Test with direct file ID

### Admin panel 404
- Check `adminConfig.enabled = true`
- Verify deployment was successful
- Clear browser cache

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 🙏 Credits

- Original concept by Parveen Bhadoo
- Redesigned and refactored to TypeScript v3.0
- Bootstrap UI framework
- Video.js, Plyr, DPlayer for media playback
- Cloudflare Workers platform

---

## 💬 Support

- **GitHub Issues:** [Report bugs](https://github.com/yourusername/google-drive-index/issues)
- **Discussions:** [Ask questions](https://github.com/yourusername/google-drive-index/discussions)
- **Telegram:** [@YourChannel](https://t.me/yourchannel)

---

## ⚠️ Important Notes

1. **Change default passwords** in `src/config.ts` and `adminConfig`
2. **Generate your own encryption keys** - don't use defaults
3. **Update KV/D1/HyperDrive IDs** in `wrangler.toml`
4. **Configure Google Drive credentials** properly
5. **Test thoroughly** before production use
6. **Backup your database** regularly (D1/HyperDrive)
7. **Keep secrets secure** - never commit API keys

---

## 🎉 Quick Deploy Checklist

- [ ] Clone repository
- [ ] Install dependencies (`npm install`)
- [ ] Choose backend (static/d1/hyperdrive)
- [ ] Update `src/config.ts`
- [ ] Generate encryption keys
- [ ] Add Google Drive credentials
- [ ] Update `wrangler.toml` (if D1/HyperDrive)
- [ ] Deploy (`npm run deploy`)
- [ ] Complete setup wizard (if D1/HyperDrive)
- [ ] Change admin password
- [ ] Test all features
- [ ] Go live! 🚀

---

<div align="center">

**Made with ❤️ for the community**

[⭐ Star on GitHub](https://github.com/yourusername/google-drive-index) • [🐛 Report Bug](https://github.com/yourusername/google-drive-index/issues) • [💡 Request Feature](https://github.com/yourusername/google-drive-index/issues)

</div>
