// Dashboard Handler for Permission Management
import { authConfig, uiConfig, dashboardConfig, megaConfig } from './config.js';

// In-memory store for permissions (in production, use KV or external DB)
let permissionsStore = {};

// Initialize permissions from config
function initPermissions() {
    // Initialize Google Drive permissions
    authConfig.roots.forEach((root, index) => {
        const key = `gd:${index}:${root.id}`;
        permissionsStore[key] = {
            type: 'google_drive',
            index: index,
            id: root.id,
            name: root.name,
            public: !root.auth,
            auth: root.auth || {},
            protect_file_link: root.protect_file_link || false
        };
    });

    // Initialize Mega.nz permissions
    if (megaConfig.roots) {
        megaConfig.roots.forEach((root, index) => {
            const key = `mega:${index}:${root.id || root.name}`;
            permissionsStore[key] = {
                type: 'mega',
                index: index,
                id: root.id || root.name,
                name: root.name,
                public: root.public !== false,
                auth: root.auth || {}
            };
        });
    }

    return permissionsStore;
}

// Dashboard HTML Template
function getDashboardHTML(permissions, message = '') {
    const permissionRows = Object.entries(permissions).map(([key, perm]) => {
        const typeIcon = perm.type === 'google_drive' ? '📁' : '☁️';
        const typeBadge = perm.type === 'google_drive' ? 
            '<span class="badge bg-primary">Google Drive</span>' : 
            '<span class="badge bg-info">Mega.nz</span>';
        const accessBadge = perm.public ? 
            '<span class="badge bg-success">Public</span>' : 
            '<span class="badge bg-warning">Auth Required</span>';
        
        return `
        <tr>
            <td>${typeIcon} ${perm.name}</td>
            <td>${typeBadge}</td>
            <td>${accessBadge}</td>
            <td>
                <code>${perm.id}</code>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="editPermission('${key}')">
                    Edit
                </button>
                <button class="btn btn-sm btn-outline-${perm.public ? 'warning' : 'success'}" 
                    onclick="toggleAccess('${key}')">
                    ${perm.public ? 'Make Private' : 'Make Public'}
                </button>
            </td>
        </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - ${authConfig.siteName}</title>
    <link rel="icon" href="${uiConfig.favicon}">
    <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.0.0/dist/${uiConfig.theme}/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-top: 80px; }
        .dashboard-header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
        }
        .card { margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stats-card { text-align: center; padding: 20px; }
        .stats-number { font-size: 2.5rem; font-weight: bold; }
        .table-responsive { border-radius: 8px; overflow: hidden; }
        .modal-header { background: #f8f9fa; }
        .permission-key { font-family: monospace; font-size: 0.85rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
        <div class="container">
            <a class="navbar-brand" href="/">${authConfig.siteName}</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link active" href="/dashboard">Dashboard</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item"><a class="nav-link" href="/dashboard/logout">Logout</a></li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="dashboard-header">
        <div class="container">
            <h1>📊 Permission Dashboard</h1>
            <p class="mb-0">Manage access permissions for your folders and files</p>
        </div>
    </div>

    <div class="container">
        ${message ? `<div class="alert alert-success alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>` : ''}

        <!-- Stats Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card bg-primary text-white">
                    <div class="stats-number">${authConfig.roots.length}</div>
                    <div>Google Drives</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card bg-info text-white">
                    <div class="stats-number">${megaConfig.roots ? megaConfig.roots.length : 0}</div>
                    <div>Mega.nz Folders</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card bg-success text-white">
                    <div class="stats-number">${Object.values(permissions).filter(p => p.public).length}</div>
                    <div>Public Access</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card bg-warning text-dark">
                    <div class="stats-number">${Object.values(permissions).filter(p => !p.public).length}</div>
                    <div>Auth Required</div>
                </div>
            </div>
        </div>

        <!-- Permissions Table -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">📂 Folder Permissions</h5>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addFolderModal">
                    + Add Folder
                </button>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Access</th>
                                <th>ID</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${permissionRows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">⚡ Quick Actions</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <button class="btn btn-outline-success w-100 mb-2" onclick="makeAllPublic()">
                            🌍 Make All Public
                        </button>
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-outline-warning w-100 mb-2" onclick="makeAllPrivate()">
                            🔒 Make All Private
                        </button>
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-outline-info w-100 mb-2" onclick="refreshPermissions()">
                            🔄 Refresh Permissions
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add User Section -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">👥 Manage Users</h5>
            </div>
            <div class="card-body">
                <form action="/dashboard/add-user" method="POST" class="row g-3">
                    <div class="col-md-3">
                        <select name="folder" class="form-select" required>
                            <option value="">Select Folder...</option>
                            ${Object.entries(permissions).map(([key, perm]) => 
                                `<option value="${key}">${perm.name}</option>`
                            ).join('')}
                        </select>
                    </div>
                    <div class="col-md-3">
                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="col-md-3">
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <div class="col-md-3">
                        <button type="submit" class="btn btn-primary w-100">Add User</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Rclone Import/Export Section -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">🔧 Rclone Configuration</h5>
                <div>
                    <button class="btn btn-outline-primary btn-sm" data-bs-toggle="modal" data-bs-target="#rcloneImportModal">
                        📥 Import
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="exportRclone()">
                        📤 Export
                    </button>
                </div>
            </div>
            <div class="card-body">
                <p class="text-muted mb-0">
                    Import drives from your existing <code>rclone.conf</code> file or export current configuration.
                    Supported remote types: <span class="badge bg-primary">drive</span> <span class="badge bg-info">mega</span>
                </p>
            </div>
        </div>

        <!-- Deployment Info -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">🚀 Deployment Info</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6>Wrangler Commands</h6>
                        <pre class="bg-dark text-light p-3 rounded"><code># Development
wrangler dev

# Deploy
wrangler deploy

# View logs
wrangler tail</code></pre>
                    </div>
                    <div class="col-md-6">
                        <h6>Quick Links</h6>
                        <ul class="list-unstyled">
                            <li><a href="https://dash.cloudflare.com/" target="_blank">☁️ Cloudflare Dashboard</a></li>
                            <li><a href="https://developers.cloudflare.com/workers/" target="_blank">📚 Workers Docs</a></li>
                            <li><a href="https://console.cloud.google.com/" target="_blank">🔑 Google Cloud Console</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Permission Modal -->
    <div class="modal fade" id="editModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Permission</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form action="/dashboard/update" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="key" id="editKey">
                        <div class="mb-3">
                            <label class="form-label">Folder Name</label>
                            <input type="text" name="name" id="editName" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Access Type</label>
                            <select name="access" id="editAccess" class="form-select">
                                <option value="public">Public (Everyone)</option>
                                <option value="private">Private (Auth Required)</option>
                            </select>
                        </div>
                        <div class="mb-3" id="authSection" style="display:none;">
                            <label class="form-label">Authorized Users (username:password, one per line)</label>
                            <textarea name="users" id="editUsers" class="form-control" rows="4"></textarea>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" name="protect_file_link" id="editProtectLink" class="form-check-input">
                            <label class="form-check-label">Protect Direct File Links</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Add Folder Modal -->
    <div class="modal fade" id="addFolderModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Folder</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form action="/dashboard/add-folder" method="POST">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Folder Type</label>
                            <select name="type" id="folderType" class="form-select" required>
                                <option value="google_drive">Google Drive</option>
                                <option value="mega">Mega.nz</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Folder Name</label>
                            <input type="text" name="name" class="form-control" required>
                        </div>
                        <div class="mb-3" id="gdIdSection">
                            <label class="form-label">Drive/Folder ID</label>
                            <input type="text" name="id" class="form-control" placeholder="e.g., 0AHm8KJX3on9JUk9PVA or root">
                        </div>
                        <div class="mb-3" id="megaLinkSection" style="display:none;">
                            <label class="form-label">Mega.nz Link</label>
                            <input type="text" name="mega_link" class="form-control" placeholder="https://mega.nz/folder/xxx#key">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Access Type</label>
                            <select name="access" class="form-select">
                                <option value="public">Public (Everyone)</option>
                                <option value="private">Private (Auth Required)</option>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Folder</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Rclone Import Modal -->
    <div class="modal fade" id="rcloneImportModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">📥 Import Rclone Configuration</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form action="/dashboard/import-rclone" method="POST">
                    <div class="modal-body">
                        <div class="alert alert-info">
                            <strong>Supported remote types:</strong> 
                            <code>drive</code> (Google Drive), <code>mega</code> (Mega.nz)
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Paste your rclone.conf content:</label>
                            <textarea name="rclone_config" class="form-control font-monospace" rows="15" 
                                placeholder="[my_gdrive]
type = drive
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
token = {...}

[my_mega]
type = mega
user = your@email.com
pass = YOUR_OBSCURED_PASSWORD" required></textarea>
                        </div>
                        <div class="form-check mb-3">
                            <input type="checkbox" name="replace_existing" class="form-check-input" id="replaceExisting">
                            <label class="form-check-label" for="replaceExisting">
                                Replace existing configuration (uncheck to merge)
                            </label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-outline-info" onclick="validateRclone()">Validate</button>
                        <button type="submit" class="btn btn-primary">Import</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Rclone Export Modal -->
    <div class="modal fade" id="rcloneExportModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">📤 Export Rclone Configuration</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <strong>Note:</strong> Sensitive data like passwords are not included. 
                        You may need to add them manually.
                    </div>
                    <textarea id="rcloneExportContent" class="form-control font-monospace" rows="15" readonly></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" onclick="copyRcloneConfig()">
                        📋 Copy to Clipboard
                    </button>
                    <button type="button" class="btn btn-success" onclick="downloadRcloneConfig()">
                        💾 Download
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const permissions = ${JSON.stringify(permissions)};

        function editPermission(key) {
            const perm = permissions[key];
            document.getElementById('editKey').value = key;
            document.getElementById('editName').value = perm.name;
            document.getElementById('editAccess').value = perm.public ? 'public' : 'private';
            document.getElementById('editProtectLink').checked = perm.protect_file_link;
            
            const users = Object.entries(perm.auth || {})
                .map(([u, p]) => u + ':' + p).join('\\n');
            document.getElementById('editUsers').value = users;
            
            toggleAuthSection();
            new bootstrap.Modal(document.getElementById('editModal')).show();
        }

        document.getElementById('editAccess').addEventListener('change', toggleAuthSection);
        
        function toggleAuthSection() {
            const access = document.getElementById('editAccess').value;
            document.getElementById('authSection').style.display = 
                access === 'private' ? 'block' : 'none';
        }

        function toggleAccess(key) {
            fetch('/dashboard/toggle-access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key })
            }).then(() => location.reload());
        }

        function makeAllPublic() {
            if (confirm('Make all folders public?')) {
                fetch('/dashboard/make-all-public', { method: 'POST' })
                    .then(() => location.reload());
            }
        }

        function makeAllPrivate() {
            if (confirm('Make all folders require authentication?')) {
                fetch('/dashboard/make-all-private', { method: 'POST' })
                    .then(() => location.reload());
            }
        }

        function refreshPermissions() {
            fetch('/dashboard/refresh', { method: 'POST' })
                .then(() => location.reload());
        }

        document.getElementById('folderType').addEventListener('change', function() {
            const isGD = this.value === 'google_drive';
            document.getElementById('gdIdSection').style.display = isGD ? 'block' : 'none';
            document.getElementById('megaLinkSection').style.display = isGD ? 'none' : 'block';
        });

        // Rclone functions
        function validateRclone() {
            const config = document.querySelector('textarea[name="rclone_config"]').value;
            fetch('/dashboard/validate-rclone', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ config })
            })
            .then(r => r.json())
            .then(result => {
                if (result.isValid) {
                    alert('✅ Configuration is valid!\\n\\nRemotes found: ' + 
                        result.remotes.map(r => r.name + ' (' + r.type + ')').join(', '));
                } else {
                    alert('❌ Configuration errors:\\n' + result.errors.join('\\n'));
                }
            })
            .catch(e => alert('Error validating: ' + e.message));
        }

        function exportRclone() {
            fetch('/dashboard/export-rclone')
                .then(r => r.text())
                .then(config => {
                    document.getElementById('rcloneExportContent').value = config;
                    new bootstrap.Modal(document.getElementById('rcloneExportModal')).show();
                });
        }

        function copyRcloneConfig() {
            const textarea = document.getElementById('rcloneExportContent');
            textarea.select();
            document.execCommand('copy');
            alert('Copied to clipboard!');
        }

        function downloadRcloneConfig() {
            const config = document.getElementById('rcloneExportContent').value;
            const blob = new Blob([config], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'rclone.conf';
            a.click();
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>`;
}

// Dashboard Login Page
function getDashboardLoginHTML(error = '') {
    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Login - ${authConfig.siteName}</title>
    <link rel="icon" href="${uiConfig.favicon}">
    <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.0.0/dist/${uiConfig.theme}/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 100%;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        .login-header p {
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h2>🔐 Dashboard Login</h2>
            <p>Enter your admin credentials</p>
        </div>
        ${error ? `<div class="alert alert-danger">${error}</div>` : ''}
        <form method="POST" action="/dashboard/login">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" name="username" class="form-control" required autofocus>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <div class="text-center mt-3">
            <a href="/" class="text-decoration-none">← Back to Home</a>
        </div>
    </div>
</body>
</html>`;
}

// Dashboard Route Handler
async function handleDashboard(request, url) {
    const path = url.pathname;
    const method = request.method;
    const cookieHeader = request.headers.get('Cookie') || '';
    const isAuthenticated = cookieHeader.includes('dashboard_auth=true');

    // Login page
    if (path === '/dashboard' || path === '/dashboard/') {
        if (!isAuthenticated) {
            return new Response(getDashboardLoginHTML(), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
        initPermissions();
        return new Response(getDashboardHTML(permissionsStore), {
            headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
    }

    // Handle login
    if (path === '/dashboard/login' && method === 'POST') {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');

        if (username === dashboardConfig.admin_username && 
            password === dashboardConfig.admin_password) {
            return new Response('', {
                status: 302,
                headers: {
                    'Location': '/dashboard',
                    'Set-Cookie': 'dashboard_auth=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400'
                }
            });
        }
        return new Response(getDashboardLoginHTML('Invalid credentials'), {
            headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
    }

    // Logout
    if (path === '/dashboard/logout') {
        return new Response('', {
            status: 302,
            headers: {
                'Location': '/dashboard',
                'Set-Cookie': 'dashboard_auth=; Path=/; HttpOnly; Max-Age=0'
            }
        });
    }

    // Protected routes - require auth
    if (!isAuthenticated) {
        return new Response('', {
            status: 302,
            headers: { 'Location': '/dashboard' }
        });
    }

    // Toggle access
    if (path === '/dashboard/toggle-access' && method === 'POST') {
        try {
            const body = await request.json();
            const key = body.key;
            if (permissionsStore[key]) {
                permissionsStore[key].public = !permissionsStore[key].public;
                // Update authConfig
                updateConfigFromPermissions();
            }
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // Update permission
    if (path === '/dashboard/update' && method === 'POST') {
        const formData = await request.formData();
        const key = formData.get('key');
        const name = formData.get('name');
        const access = formData.get('access');
        const users = formData.get('users') || '';
        const protectLink = formData.get('protect_file_link') === 'on';

        if (permissionsStore[key]) {
            permissionsStore[key].name = name;
            permissionsStore[key].public = access === 'public';
            permissionsStore[key].protect_file_link = protectLink;
            
            // Parse users
            const auth = {};
            users.split('\n').forEach(line => {
                const [u, p] = line.trim().split(':');
                if (u && p) auth[u] = p;
            });
            permissionsStore[key].auth = auth;
            
            updateConfigFromPermissions();
        }

        return new Response('', {
            status: 302,
            headers: { 'Location': '/dashboard' }
        });
    }

    // Add user
    if (path === '/dashboard/add-user' && method === 'POST') {
        const formData = await request.formData();
        const folder = formData.get('folder');
        const username = formData.get('username');
        const password = formData.get('password');

        if (permissionsStore[folder]) {
            permissionsStore[folder].auth = permissionsStore[folder].auth || {};
            permissionsStore[folder].auth[username] = password;
            updateConfigFromPermissions();
        }

        return new Response('', {
            status: 302,
            headers: { 'Location': '/dashboard' }
        });
    }

    // Make all public
    if (path === '/dashboard/make-all-public' && method === 'POST') {
        Object.keys(permissionsStore).forEach(key => {
            permissionsStore[key].public = true;
        });
        updateConfigFromPermissions();
        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Make all private
    if (path === '/dashboard/make-all-private' && method === 'POST') {
        Object.keys(permissionsStore).forEach(key => {
            permissionsStore[key].public = false;
        });
        updateConfigFromPermissions();
        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Refresh permissions
    if (path === '/dashboard/refresh' && method === 'POST') {
        permissionsStore = {};
        initPermissions();
        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Validate rclone config
    if (path === '/dashboard/validate-rclone' && method === 'POST') {
        try {
            const body = await request.json();
            const { validateRcloneConfig } = await import('./rclone.js');
            const result = validateRcloneConfig(body.config);
            return new Response(JSON.stringify(result), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ isValid: false, errors: [e.message] }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // Export rclone config
    if (path === '/dashboard/export-rclone' && method === 'GET') {
        try {
            const { exportToRcloneConfig } = await import('./rclone.js');
            const config = exportToRcloneConfig();
            return new Response(config, {
                headers: { 'Content-Type': 'text/plain' }
            });
        } catch (e) {
            return new Response('# Error generating config: ' + e.message, {
                headers: { 'Content-Type': 'text/plain' }
            });
        }
    }

    // Import rclone config
    if (path === '/dashboard/import-rclone' && method === 'POST') {
        try {
            const formData = await request.formData();
            const rcloneConfig = formData.get('rclone_config');
            const replaceExisting = formData.get('replace_existing') === 'on';
            
            const { importRcloneConfig, validateRcloneConfig } = await import('./rclone.js');
            
            // Validate first
            const validation = validateRcloneConfig(rcloneConfig);
            if (!validation.isValid) {
                return new Response(getDashboardHTML(permissionsStore, 
                    '❌ Invalid configuration: ' + validation.errors.join(', ')), {
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
                });
            }
            
            // Import
            const imported = importRcloneConfig(rcloneConfig);
            
            // Add to config
            if (replaceExisting) {
                // Replace existing roots
                if (imported.googleDriveRoots.length > 0) {
                    authConfig.roots = imported.googleDriveRoots;
                }
                if (imported.megaRoots.length > 0) {
                    megaConfig.roots = imported.megaRoots;
                }
            } else {
                // Merge with existing
                imported.googleDriveRoots.forEach(root => {
                    authConfig.roots.push(root);
                });
                if (megaConfig.roots) {
                    imported.megaRoots.forEach(root => {
                        megaConfig.roots.push(root);
                    });
                } else {
                    megaConfig.roots = imported.megaRoots;
                }
            }
            
            // Update tokens if available
            if (imported.googleDriveTokens) {
                if (imported.googleDriveTokens.client_id) {
                    authConfig.client_id = imported.googleDriveTokens.client_id;
                }
                if (imported.googleDriveTokens.client_secret) {
                    authConfig.client_secret = imported.googleDriveTokens.client_secret;
                }
                if (imported.googleDriveTokens.refresh_token) {
                    authConfig.refresh_token = imported.googleDriveTokens.refresh_token;
                }
            }
            
            // Refresh permissions
            permissionsStore = {};
            initPermissions();
            
            const message = `✅ Imported ${imported.googleDriveRoots.length} Google Drive(s) and ${imported.megaRoots.length} Mega.nz folder(s)` +
                (imported.errors.length > 0 ? '. Warnings: ' + imported.errors.join(', ') : '');
            
            return new Response(getDashboardHTML(permissionsStore, message), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            return new Response(getDashboardHTML(permissionsStore, '❌ Import error: ' + e.message), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    return new Response('Not Found', { status: 404 });
}

// Update authConfig from permissions store
function updateConfigFromPermissions() {
    Object.entries(permissionsStore).forEach(([key, perm]) => {
        if (perm.type === 'google_drive') {
            const root = authConfig.roots[perm.index];
            if (root) {
                root.name = perm.name;
                root.protect_file_link = perm.protect_file_link;
                if (perm.public) {
                    delete root.auth;
                } else {
                    root.auth = perm.auth;
                }
            }
        } else if (perm.type === 'mega' && megaConfig.roots) {
            const root = megaConfig.roots[perm.index];
            if (root) {
                root.name = perm.name;
                root.public = perm.public;
                root.auth = perm.auth;
            }
        }
    });
}

// Get current permissions
function getPermissions() {
    if (Object.keys(permissionsStore).length === 0) {
        initPermissions();
    }
    return permissionsStore;
}

// Check if path requires auth based on permissions
function requiresAuth(driveType, index) {
    initPermissions();
    const key = driveType === 'google_drive' ? 
        `gd:${index}:${authConfig.roots[index]?.id}` :
        `mega:${index}:${megaConfig.roots?.[index]?.id || megaConfig.roots?.[index]?.name}`;
    
    const perm = permissionsStore[key];
    return perm ? !perm.public : false;
}

export {
    handleDashboard,
    initPermissions,
    getPermissions,
    requiresAuth,
    permissionsStore
};
