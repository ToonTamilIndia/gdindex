# GDIndex

Google Drive + Mega.nz index running on Cloudflare Workers. Comes with a dashboard for permissions, theme switcher, ad gate, and rclone config import.

[![Stars](https://img.shields.io/github/stars/ToonTamilIndia/gdindex?style=flat-square)](https://github.com/ToonTamilIndia/gdindex)
[![License](https://img.shields.io/github/license/ToonTamilIndia/gdindex?style=flat-square)](LICENSE)

## Files

```
index.js            routes and main logic
config.example.js   copy this to config.js and fill your stuff
config.js           your creds (gitignored)
utils.js            helpers
templates.js        html templates
googleDrive.js      google drive api
megaDrive.js        mega.nz api
adGate.js           ad shortener gate with kv
dashboard.js        permission dashboard
auth.js             basic auth + auth0
rclone.js           parse rclone.conf
wrangler.toml       cloudflare config
```

## Quick Deploy

```bash
npm install -g wrangler
wrangler login

git clone https://github.com/ToonTamilIndia/gdindex.git
cd gdindex

cp config.example.js config.js
# edit config.js with your google drive api creds

wrangler deploy
```

Check `wrangler.toml` before deploying -- you may need to add KV namespace bindings for auth sessions or the ad gate.

## Config

### Google Drive

```javascript
const authConfig = {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "client_secret": "YOUR_CLIENT_SECRET",
    "refresh_token": "YOUR_REFRESH_TOKEN",
    "roots": [
        { "id": "root", "name": "My Drive" },
        { "id": "SHARED_DRIVE_ID", "name": "Team Drive" }
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
        { "link": "https://mega.nz/folder/ID#KEY", "name": "Mega Folder", "public": true }
    ]
};
```

### Rclone Import

Go to `/dashboard` -> Import/Export, paste your rclone.conf, click Import. Works with `drive` and `mega` remotes.

```ini
[my_gdrive]
type = drive
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
token = {"access_token":"...","refresh_token":"..."}
```

## Routes

| Path | What it does |
|------|-------------|
| `/` | Home -- lists all drives |
| `/0:/` | First google drive root |
| `/1:/path/to/file` | Second google drive, specific path |
| `/mega0:/` | First mega.nz root |
| `/dashboard` | Permission management |
| `/0:search?q=query` | Search within a drive |

## Auth

Per-folder basic auth:

```javascript
{ "id": "folder_id", "name": "Private", "auth": { "user1": "password1" } }
```

Auth0 is also supported -- check `auth0Config` in config.example.js and set `enable_auth0_com: true`.

## Themes

```javascript
const uiConfig = { "theme": "slate", "default_player": "plyr" };
```

Pick from cerulean, cosmo, cyborg, darkly, flatly, slate, solar, superhero, vapor, etc. `dark` maps to `darkly`.

## Ad Gate

Disabled by default. Set `adConfig.enabled = true` with your GPLinks API token, create a KV namespace (`wrangler kv:namespace create LINK_STORE`), and add the binding to wrangler.toml.

## Dashboard Secrets

Better to use wrangler secrets than hardcoding in config.js:

```bash
wrangler secret put DASHBOARD_ADMIN_USERNAME
wrangler secret put DASHBOARD_ADMIN_PASSWORD
wrangler secret put DASHBOARD_SESSION_SECRET
```

## Dev

```bash
wrangler dev        # local at localhost:8787
npx esbuild index.js --bundle --outfile=worker.js --format=esm   # single-file bundle
```

## Troubleshooting

- **No access token** -- check your client_id/secret/refresh_token
- **Shared drive not found** -- id should start with `0A`, make sure the account has access
- **KV namespace not found** -- create it and add the binding
- **CORS errors** -- set `enable_cors_file_down: true`

Add `DEBUG = "true"` to `[vars]` in wrangler.toml for verbose logs.

## License

MIT
