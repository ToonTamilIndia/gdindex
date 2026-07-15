<p align="center">
  <a href="https://github.com/ToonTamilIndia/gdindex">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&duration=2600&pause=800&color=38BDF8&center=true&vCenter=true&width=900&lines=ToonTamilIndia+GDIndex;Google+Drive+%2B+Mega.nz+Media+Index;Dashboard+Themes+%2B+Ad+Gate+%2B+JWPlayer" alt="ToonTamilIndia GDIndex typing banner" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/JavaScript-ESM-F7DF1E?style=for-the-badge&logo=javascript&logoColor=111" alt="JavaScript" />
  <img src="https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare" />
  <img src="https://img.shields.io/badge/Google_Drive-API-4285F4?style=for-the-badge&logo=googledrive&logoColor=white" alt="Google Drive" />
  <img src="https://img.shields.io/badge/Mega.nz-Supported-D9272E?style=for-the-badge&logo=mega&logoColor=white" alt="Mega.nz" />
  <img src="https://img.shields.io/badge/Bootstrap-Bootswatch-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white" alt="Bootstrap" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" />
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/ToonTamilIndia/gdindex?style=flat-square&color=f97316" alt="Stars" />
  <img src="https://img.shields.io/github/forks/ToonTamilIndia/gdindex?style=flat-square&color=3b82f6" alt="Forks" />
  <img src="https://img.shields.io/github/issues/ToonTamilIndia/gdindex?style=flat-square&color=ef4444" alt="Issues" />
  <img src="https://img.shields.io/github/last-commit/ToonTamilIndia/gdindex?style=flat-square&color=22c55e" alt="Last Commit" />
  <img src="https://img.shields.io/github/repo-size/ToonTamilIndia/gdindex?style=flat-square&color=8b5cf6" alt="Repo Size" />
</p>

> A Cloudflare Workers-based Google Drive and Mega.nz media index with a permission management dashboard, customizable themes, ad-gate support, and rclone config import.

## Table of Contents

- [Features](#features)
- [File Structure](#file-structure)
- [Requirements](#requirements)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Themes](#themes)
- [Ad Shortener Gate](#ad-shortener-gate)
- [Dashboard](#dashboard)
- [URL Structure](#url-structure)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Google Drive Index** -- Browse and stream files from Google Drive
- **Mega.nz Support** -- Access Mega.nz cloud storage
- **Permission Dashboard** -- Manage folder access permissions
- **Rclone Import** -- Import configuration from rclone.conf
- **Multiple Themes** -- Choose from 26+ Bootswatch themes
- **Authentication** -- Basic auth and Auth0 integration
- **Media Player** -- Built-in Plyr or JWPlayer
- **Search** -- Full-text search across drives
- **Ad Gate** -- Optional GPLinks shortener flow with KV-backed return IDs

## File Structure

```
├── index.js            Main entry point and route handler
├── config.example.js   Configuration template (copy to config.js)
├── config.js           Your configuration (gitignored)
├── utils.js            Utility functions
├── templates.js        HTML templates
├── googleDrive.js      Google Drive API handler
├── megaDrive.js        Mega.nz API handler
├── adGate.js           KV-backed ad shortener gate
├── dashboard.js        Permission management dashboard
├── auth.js             Authentication handlers
├── rclone.js           Rclone config parser
├── wrangler.toml       Cloudflare Wrangler config
└── README.md           This file
```

## Requirements

- Node.js 16+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)
- Cloudflare account
- Google Cloud project with Drive API enabled
- (Optional) Mega.nz account
- (Optional) Auth0 tenant

## Deployment

### Wrangler CLI

```bash
npm install -g wrangler
wrangler login

git clone https://github.com/ToonTamilIndia/gdindex.git
cd gdindex

cp config.example.js config.js
# Edit config.js with your credentials

wrangler deploy
```

### wrangler.toml

```toml
name = "gdindex"
main = "index.js"
compatibility_date = "2024-01-01"
compatibility_flags = ["nodejs_compat"]

# [[kv_namespaces]]
# binding = "AUTH_STORE"
# id = "your-auth-store-id"

# [[kv_namespaces]]
# binding = "LINK_STORE"
# id = "your-link-store-id"
```

## Configuration

Copy the template and fill in your credentials:

```bash
cp config.example.js config.js
```

### Google Drive

```javascript
const authConfig = {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "client_secret": "YOUR_CLIENT_SECRET",
    "refresh_token": "YOUR_REFRESH_TOKEN",
    "roots": [
        {
            "id": "root",
            "name": "My Drive"
        },
        {
            "id": "SHARED_DRIVE_ID",
            "name": "Team Drive"
        }
    ]
};
```

### Mega.nz

```javascript
const megaConfig = {
    "enabled": true,
    "accounts": [
        { "email": "your@email.com", "password": "yourpassword" }
    ],
    "roots": [
        {
            "link": "https://mega.nz/folder/ID#KEY",
            "name": "Mega Folder",
            "public": true
        }
    ]
};
```

### Rclone Import

Open Dashboard at `/dashboard`, go to Import/Export, paste your rclone.conf content, and click Import.

Supported remotes: `drive` (Google Drive), `mega` (Mega.nz).

```ini
[my_gdrive]
type = drive
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
token = {"access_token":"...","refresh_token":"..."}
team_drive = SHARED_DRIVE_ID
```

## Authentication

### Basic Auth (Per Folder)

```javascript
{
    "id": "folder_id",
    "name": "Private Folder",
    "auth": {
        "user1": "password1"
    }
}
```

### Auth0

```javascript
const auth0Config = {
    domain: "your-tenant.auth0.com",
    clientId: "YOUR_CLIENT_ID",
    clientSecret: "YOUR_CLIENT_SECRET",
    callbackUrl: "https://yoursite.com/auth",
    logoutUrl: "https://yoursite.com"
};

// In authConfig:
"enable_auth0_com": true
```

Create a KV namespace and add the binding to wrangler.toml:

```bash
wrangler kv:namespace create AUTH_STORE
```

## Themes

```javascript
const uiConfig = {
    "theme": "slate", // cerulean, cosmo, cyborg, darkly, flatly, ...
    "default_player": "plyr" // plyr or jwplayer
};
```

Available themes: cerulean, cosmo, cyborg, dark, darkly, flatly, journal, litera, lumen, lux, materia, minty, morph, pulse, quartz, sandstone, simplex, sketchy, slate, solar, spacelab, superhero, united, vapor, yeti, zephyr.

`dark` is accepted as a dashboard-friendly alias for Bootswatch `darkly`.

## Ad Shortener Gate

Disabled by default. When enabled, file view links are valid for 10 minutes and direct download links for 30 minutes.

```javascript
const adConfig = {
    "enabled": false,
    "provider": "gplinks",
    "api_token": "YOUR_GPLINKS_API_TOKEN",
    "min_wait_seconds": 10,
    "view_expiry_seconds": 600,
    "download_expiry_seconds": 1800
};
```

Create a KV namespace:

```bash
wrangler kv:namespace create LINK_STORE
```

Add binding to wrangler.toml and enable from the dashboard.

## Dashboard

Access at `/dashboard`. Features:

- View all configured drives (Google Drive and Mega.nz)
- Toggle public/private access per folder
- Add/remove users for private folders
- Import rclone configuration
- Change theme, player, and ad-gate settings
- Browserless health check and MEGA upload management

Dashboard secrets (recommended over config.js):

```bash
wrangler secret put DASHBOARD_ADMIN_USERNAME
wrangler secret put DASHBOARD_ADMIN_PASSWORD
wrangler secret put DASHBOARD_SESSION_SECRET
```

## URL Structure

| Route | Description |
|-------|-------------|
| `/` | Homepage with drive list |
| `/0:/` | First Google Drive root |
| `/1:/path/to/file` | Second Google Drive, specific path |
| `/mega0:/` | First Mega.nz root |
| `/dashboard` | Permission management dashboard |
| `/0:search?q=query` | Search in first drive |

## Development

```bash
wrangler dev
# Opens at http://localhost:8787
```

### Single-file bundle

```bash
npx esbuild index.js --bundle --outfile=worker.js --format=esm
```

### Environment secrets

```bash
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put REFRESH_TOKEN
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No access token | Check client_id, client_secret, and refresh_token |
| Shared Drive not found | Verify the Drive ID starts with `0A` and the account has access |
| KV namespace not found | Create the namespace and add binding to wrangler.toml |
| CORS errors | Enable `enable_cors_file_down` in config.js |

Add `DEBUG = "true"` to wrangler.toml `[vars]` for verbose logging.

## License

MIT License. See [LICENSE](LICENSE) for details.
