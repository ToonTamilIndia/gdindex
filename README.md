# 📁 GDIndex - Google Drive Index with Mega.nz Support

A feature-rich Google Drive & Mega.nz index running on Cloudflare Workers, featuring a permission management dashboard, rclone configuration support, and beautiful UI.

![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)

## ✨ Features

- 📂 **Google Drive Index** - Browse and stream files from Google Drive
- ☁️ **Mega.nz Support** - Access Mega.nz cloud storage
- 🔐 **Permission Dashboard** - Manage folder access permissions
- 🔧 **Rclone Support** - Import configuration from rclone.conf
- 🎨 **Beautiful Themes** - Multiple Bootstrap themes
- 🔒 **Authentication** - Basic auth and Auth0 integration
- 📱 **Responsive Design** - Works on all devices
- 🎬 **Media Player** - Built-in video/audio player
- 🔍 **Search** - Full-text search across drives

## 📁 File Structure

```
├── index.js          # Main entry point & route handler
├── config.js         # All configuration settings
├── utils.js          # Utility functions
├── templates.js      # HTML templates
├── googleDrive.js    # Google Drive API handler
├── megaDrive.js      # Mega.nz API handler
├── dashboard.js      # Permission management dashboard
├── auth.js           # Authentication handlers
├── rclone.js         # Rclone config parser
├── wrangler.toml     # Cloudflare Wrangler config
└── README.md         # This file
```

## 🚀 Deployment

### Option 1: Cloudflare Dashboard (Easy)

1. Go to [Cloudflare Workers Dashboard](https://dash.cloudflare.com/)
2. Create a new Worker
3. Copy the content of all `.js` files
4. Click **Save and Deploy**

### Option 2: Wrangler CLI (Recommended)

#### Prerequisites

```bash
# Install Node.js (v16+)
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login
```

#### Setup

1. **Clone or download this repository**

```bash
git clone https://github.com/YourUsername/gdindex.git
cd gdindex
```

2. **Create wrangler.toml**

```bash
cp wrangler.example.toml wrangler.toml
```

3. **Configure wrangler.toml**

```toml
name = "gdindex"
main = "index.js"
compatibility_date = "2024-01-01"
compatibility_flags = ["nodejs_compat"]

# Optional: KV Namespace for Auth0
# [[kv_namespaces]]
# binding = "AUTH_STORE"
# id = "your-kv-namespace-id"

# Optional: Custom domain
# routes = [
#   { pattern = "files.yourdomain.com/*", zone_name = "yourdomain.com" }
# ]
```

4. **Deploy**

```bash
# Development (local)
wrangler dev

# Production
wrangler deploy
```

### Option 3: GitHub Actions (CI/CD)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Cloudflare Workers

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - name: Install Wrangler
        run: npm install -g wrangler
        
      - name: Deploy
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        run: wrangler deploy
```

Add `CLOUDFLARE_API_TOKEN` to your repository secrets.

## ⚙️ Configuration

### config.js

Edit `config.js` to configure your drives:

```javascript
// Google Drive Configuration
const authConfig = {
    "siteName": "My Drive Index",
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "client_secret": "YOUR_CLIENT_SECRET",
    "refresh_token": "YOUR_REFRESH_TOKEN",
    "roots": [
        {
            "id": "root",
            "name": "My Drive",
            "auth": { "user": "password" }  // Optional auth
        },
        {
            "id": "SHARED_DRIVE_ID",
            "name": "Team Drive",
            "protect_file_link": true
        }
    ]
};

// Mega.nz Configuration
const megaConfig = {
    "enabled": true,
    "accounts": [
        { "email": "your@email.com", "password": "yourpassword" }
    ],
    "roots": [
        { "id": "folder_id", "name": "Mega Folder", "public": true }
    ]
};

// Dashboard Admin
const dashboardConfig = {
    "admin_username": "admin",
    "admin_password": "change_this_password"
};
```

### Using Rclone Configuration

You can import settings from your existing rclone.conf:

1. Open the Dashboard at `/dashboard`
2. Go to Import/Export settings
3. Paste your rclone.conf content
4. Click Import

**Supported rclone remote types:**
- `drive` - Google Drive
- `mega` - Mega.nz

Example rclone.conf:
```ini
[my_gdrive]
type = drive
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
token = {"access_token":"...","refresh_token":"..."}
team_drive = SHARED_DRIVE_ID

[my_mega]
type = mega
user = your@email.com
pass = OBSCURED_PASSWORD
```

## 🔗 URL Structure

| Route | Description |
|-------|-------------|
| `/` | Homepage with drive list |
| `/0:/` | First Google Drive root |
| `/1:/path/to/file` | Second Google Drive, specific path |
| `/mega0:/` | First Mega.nz root |
| `/dashboard` | Permission management dashboard |
| `/0:search?q=query` | Search in first drive |

## 🔐 Authentication

### Basic Auth (Per Folder)

Add auth to any root in `config.js`:

```javascript
{
    "id": "folder_id",
    "name": "Private Folder",
    "auth": {
        "user1": "password1",
        "user2": "password2"
    }
}
```

### Auth0 Integration

1. Create an Auth0 application
2. Configure in `config.js`:

```javascript
const auth0Config = {
    domain: "your-tenant.auth0.com",
    clientId: "YOUR_CLIENT_ID",
    clientSecret: "YOUR_CLIENT_SECRET",
    callbackUrl: "https://yoursite.com/auth",
    logoutUrl: "https://yoursite.com"
};

// Enable in authConfig
const authConfig = {
    "enable_auth0_com": true,
    // ...
};
```

3. Create KV namespace for session storage:

```bash
wrangler kv:namespace create AUTH_STORE
```

4. Add to wrangler.toml:

```toml
[[kv_namespaces]]
binding = "AUTH_STORE"
id = "your-namespace-id"
```

## 🎨 Themes

Change theme in `config.js`:

```javascript
const uiConfig = {
    "theme": "slate",  // Options: cerulean, cosmo, cyborg, darkly, 
                       // flatly, journal, litera, lumen, lux, materia,
                       // minty, morph, pulse, quartz, sandstone, simplex,
                       // sketchy, slate, solar, spacelab, superhero,
                       // united, vapor, yeti, zephyr
};
```

## 📊 Dashboard

Access the dashboard at `/dashboard` to:

- ✅ View all configured drives (Google Drive & Mega.nz)
- 🔄 Toggle public/private access per folder
- 👥 Add/remove users for private folders
- ⚡ Quick actions (make all public/private)
- 📥 Import rclone configuration

Default credentials: `admin` / `admin123` (change in config.js!)

## 🛠️ Development

### Local Development

```bash
# Install dependencies
npm install -g wrangler

# Run locally
wrangler dev

# Open http://localhost:8787
```

### Building for Production

For a single-file deployment:

```bash
# Bundle all files (requires esbuild or similar)
npx esbuild index.js --bundle --outfile=worker.js --format=esm
```

## 📋 Environment Variables

For sensitive data, use Wrangler secrets:

```bash
# Set secrets
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put REFRESH_TOKEN
wrangler secret put DASHBOARD_PASSWORD

# Use in code
const secret = env.GOOGLE_CLIENT_SECRET;
```

## 🔧 Troubleshooting

### Common Issues

1. **"Error: No access token"**
   - Check your `client_id`, `client_secret`, and `refresh_token`
   - Ensure OAuth consent screen is properly configured

2. **"Shared Drive not found"**
   - Use the correct Shared Drive ID (starts with `0A`)
   - Ensure the account has access to the Shared Drive

3. **"KV namespace not found"**
   - Create KV namespace: `wrangler kv:namespace create AUTH_STORE`
   - Add binding to wrangler.toml

4. **CORS errors**
   - Enable CORS in config: `"enable_cors_file_down": true`

### Debug Mode

Add to wrangler.toml for verbose logging:

```toml
[vars]
DEBUG = "true"
```

## 📜 License

MIT License - feel free to use and modify.

## 🙏 Credits

- Original [GOIndex](https://github.com/donwa/goindex) by donwa
- Redesigned by [Parveen Bhadoo](https://github.com/AnshumanHeroapple)
- UI powered by [Bootstrap](https://getbootstrap.com/) & [Bootswatch](https://bootswatch.com/)
- Video player by [Plyr](https://plyr.io/)

## 🔗 Links

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Wrangler CLI Docs](https://developers.cloudflare.com/workers/wrangler/)
- [Google Drive API](https://developers.google.com/drive/api)
- [Mega.nz SDK](https://mega.nz/sdk)

---

<p align="center">
  Made with ❤️ for the community
</p>
