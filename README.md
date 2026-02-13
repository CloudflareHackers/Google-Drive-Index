# Google Drive Index

A serverless Google Drive directory listing built on **Cloudflare Pages** with **D1** database.

## Architecture

```
/                    → index.html (SPA frontend)
/login/              → handled by index.html + app.js
/admin/              → handled by index.html + app.js
/search?q=...        → handled by index.html + app.js
/api/status          → GET  - app status & auth check
/api/setup           → POST - first-time admin setup
/api/login           → POST - admin login
/api/logout          → POST - logout
/api/files           → GET  - list files in a drive/folder
/api/file            → GET  - get single file metadata
/api/search          → GET  - search files
/api/admin/drives    → CRUD - manage drives
/api/admin/config    → GET/POST - site configuration
/api/admin/password  → POST - change admin password
/download/{drive}/{id} → file download/stream
/assets/*            → static assets (JS, CSS, icons)
```

## Setup

### 1. Create D1 Database

```bash
npx wrangler d1 create drive-index-db
```

Update `wrangler.toml` with the database ID.

### 2. Install Dependencies

```bash
npm install
```

### 3. Deploy

```bash
npm run deploy
```

### 4. First-Time Setup

Visit your deployed site. You'll be prompted to create an admin account with a strong password (8+ chars, uppercase, lowercase, number, special character).

### 5. Add Drives

Log in to `/admin/` and add your Google Drive credentials:
- **Name**: Display name
- **Client ID**: From Google Cloud Console
- **Client Secret**: From Google Cloud Console  
- **Refresh Token**: OAuth2 refresh token
- **Root Folder ID**: Drive/folder ID or `root`

## Features

- **Multi-drive support**: Add multiple Google Drive accounts
- **File browsing**: Navigate folders with breadcrumb navigation
- **Search**: Search across all drives
- **Download**: Direct file download/streaming
- **Admin panel**: Manage drives, configuration, and passwords
- **Auth system**: Cookie-based HMAC authentication
- **No hardcoded secrets**: Everything configured via admin panel after first setup
- **D1 database**: All config stored in Cloudflare D1
- **Auto DB init**: Tables created automatically on first request

## Project Structure

```
├── dist/                  # Static assets (Pages build output)
│   ├── index.html         # SPA shell
│   ├── _routes.json       # Pages routing config
│   ├── _headers           # Cache headers
│   └── assets/
│       ├── app.js         # Frontend application
│       └── favicon.svg    # Favicon
├── functions/             # Cloudflare Pages Functions
│   ├── _middleware.ts     # DB init + CORS middleware
│   ├── api/
│   │   ├── setup.ts       # First-time setup
│   │   ├── login.ts       # Authentication
│   │   ├── logout.ts      # Logout
│   │   ├── status.ts      # App status
│   │   ├── files.ts       # File listing
│   │   ├── file.ts        # Single file metadata
│   │   ├── search.ts      # Search
│   │   └── admin/
│   │       ├── drives.ts  # Drive CRUD
│   │       ├── config.ts  # Config management
│   │       └── password.ts # Password change
│   ├── download/
│   │   └── [[path]].ts   # File download handler
│   └── lib/
│       ├── auth.ts        # Auth utilities
│       ├── db.ts          # Database helpers
│       └── drive.ts       # Google Drive API
├── schema.sql             # D1 schema (reference)
├── wrangler.toml          # Cloudflare config
├── package.json
└── tsconfig.json
```

## Local Development

```bash
npm run dev
```

## License

MIT