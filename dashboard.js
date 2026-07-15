// Dashboard Handler for Permission Management
import { authConfig, uiConfig, dashboardConfig, megaConfig, adConfig, browserlessConfig, megaUploadConfig, pathPasswordConfig } from './config.js';
import { normalizeTheme, saveRuntimeSettings } from './adGate.js';

// In-memory store for permissions (in production, use KV or external DB)
let permissionsStore = {};
let megaUploadCursor = 0;
const DASHBOARD_COOKIE_NAME = 'dashboard_auth';
const DASHBOARD_SESSION_TTL_SECONDS = 86400;
const DEFAULT_SESSION_SECRET = 'your-secret-key-here';

function escapeHTML(value = '') {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function normalizeProtectedPath(path = '/') {
    let clean = '/' + String(path || '/').trim().replace(/^\/+/, '');
    clean = clean.replace(/\/{2,}/g, '/');
    return clean.endsWith('/') || clean.includes('.') ? clean : clean + '/';
}

function randomPassword(length = 20) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => alphabet[byte % alphabet.length]).join('');
}

function runtimeSettingsSnapshot() {
    return {
        ui: {
            theme: uiConfig.theme,
            default_player: uiConfig.default_player,
            jwplayer_script: uiConfig.jwplayer_script
        },
        ad: {
            enabled: adConfig.enabled,
            api_token: adConfig.api_token,
            min_wait_seconds: adConfig.min_wait_seconds,
            view_expiry_seconds: adConfig.view_expiry_seconds,
            download_expiry_seconds: adConfig.download_expiry_seconds,
            require_return_referer: adConfig.require_return_referer,
            allowed_return_referers: adConfig.allowed_return_referers
        },
        browserless: {
            enabled: browserlessConfig.enabled,
            endpoint: browserlessConfig.endpoint,
            api_token: browserlessConfig.api_token,
            timeout_seconds: browserlessConfig.timeout_seconds
        },
        megaUpload: {
            enabled: megaUploadConfig.enabled,
            admin_only: true,
            mode: 'configured_accounts',
            pool_name: megaUploadConfig.pool_name,
            target_strategy: megaUploadConfig.target_strategy,
            max_upload_mb: megaUploadConfig.max_upload_mb,
            allow_automated_account_creation: megaUploadConfig.allow_automated_account_creation
        },
        megaAccounts: megaConfig.accounts || [],
        googleRoots: authConfig.roots || [],
        megaRoots: megaConfig.roots || [],
        pathPasswords: pathPasswordConfig
    };
}

async function persistRuntimeSettings(env) {
    await saveRuntimeSettings(env, runtimeSettingsSnapshot());
}

function getAdminCredentials(env = {}) {
    return {
        username: env.DASHBOARD_ADMIN_USERNAME || env.DASHBOARD_USERNAME || dashboardConfig.admin_username,
        password: env.DASHBOARD_ADMIN_PASSWORD || env.DASHBOARD_PASSWORD || dashboardConfig.admin_password
    };
}

function parseBasicAuth(request) {
    const header = request.headers.get('Authorization') || '';
    if (!header.toLowerCase().startsWith('basic ')) return null;
    try {
        const decoded = atob(header.split(' ').pop());
        const separator = decoded.indexOf(':');
        if (separator < 0) return null;
        return {
            username: decoded.slice(0, separator),
            password: decoded.slice(separator + 1)
        };
    } catch {
        return null;
    }
}

function isAdminBasicAuthenticated(request, env = {}) {
    const credentials = parseBasicAuth(request);
    if (!credentials) return false;
    const admin = getAdminCredentials(env);
    return credentials.username === admin.username && credentials.password === admin.password;
}

function getDashboardSessionSecret(env = {}) {
    const secret = env.DASHBOARD_SESSION_SECRET || dashboardConfig.session_secret;
    if (!secret || secret === DEFAULT_SESSION_SECRET || String(secret).length < 32) {
        console.warn('Dashboard session secret is missing, default, or too short. Set DASHBOARD_SESSION_SECRET with wrangler secret put.');
    }
    return String(secret || DEFAULT_SESSION_SECRET);
}

function base64UrlEncodeBytes(bytes) {
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlEncodeString(value) {
    return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeString(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
}

async function signDashboardValue(value, secret) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
    return base64UrlEncodeBytes(new Uint8Array(signature));
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return mismatch === 0;
}

function getCookieValue(request, name) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const prefix = `${name}=`;
    const cookie = cookieHeader
        .split(';')
        .map(item => item.trim())
        .find(item => item.startsWith(prefix));
    return cookie ? cookie.slice(prefix.length) : '';
}

async function createDashboardSessionToken(username, env = {}) {
    const now = Math.floor(Date.now() / 1000);
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    const payload = base64UrlEncodeString(JSON.stringify({
        u: username,
        iat: now,
        exp: now + DASHBOARD_SESSION_TTL_SECONDS,
        n: base64UrlEncodeBytes(nonce)
    }));
    const signature = await signDashboardValue(payload, getDashboardSessionSecret(env));
    return `${payload}.${signature}`;
}

async function verifyDashboardSessionToken(token, env = {}) {
    if (!token || !token.includes('.')) return false;
    const [payload, signature] = token.split('.');
    if (!payload || !signature) return false;
    const expected = await signDashboardValue(payload, getDashboardSessionSecret(env));
    if (!timingSafeEqual(signature, expected)) return false;
    try {
        const data = JSON.parse(base64UrlDecodeString(payload));
        const admin = getAdminCredentials(env);
        const now = Math.floor(Date.now() / 1000);
        return data.u === admin.username && Number(data.exp) > now;
    } catch {
        return false;
    }
}

function adminAuthResponse() {
    return new Response('Unauthorized', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Basic realm="GDIndex Admin"' }
    });
}

async function callBrowserlessFunction(code) {
    if (!browserlessConfig.enabled) throw new Error('Browserless is disabled.');
    if (!browserlessConfig.api_token) throw new Error('Browserless API token is missing.');

    const endpoint = String(browserlessConfig.endpoint || 'https://production-sfo.browserless.io').replace(/\/+$/, '');
    const apiUrl = `${endpoint}/function?token=${encodeURIComponent(browserlessConfig.api_token)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(browserlessConfig.timeout_seconds || 120) * 1000);
    const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/javascript' },
        body: code,
        signal: controller.signal
    });
    clearTimeout(timeout);
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`Browserless returned HTTP ${res.status}: ${text.slice(0, 300)}`);
    }
    try {
        return JSON.parse(text);
    } catch {
        return { data: text };
    }
}

function icon(name) {
    const icons = {
        dashboard: '<svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10Z"/><path d="M13 21h8V11h-8v10Z"/><path d="M13 3v6h8V3h-8Z"/><path d="M3 21h8v-6H3v6Z"/></svg>',
        folder: '<svg viewBox="0 0 24 24"><path d="M3 6.5A2.5 2.5 0 0 1 5.5 4H9l2 2h7.5A2.5 2.5 0 0 1 21 8.5v8A3.5 3.5 0 0 1 17.5 20h-11A3.5 3.5 0 0 1 3 16.5v-10Z"/></svg>',
        cloud: '<svg viewBox="0 0 24 24"><path d="M17.5 19H8a5 5 0 0 1-.9-9.92A6.5 6.5 0 0 1 19.5 11.5 3.75 3.75 0 0 1 17.5 19Z"/></svg>',
        bolt: '<svg viewBox="0 0 24 24"><path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z"/></svg>',
        users: '<svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
        settings: '<svg viewBox="0 0 24 24"><path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5Z"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6V20a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-.6 1.7 1.7 0 0 0-1.88.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-.6-1H4a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 .6-1 1.7 1.7 0 0 0-.34-1.88l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-.6V4a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 .6 1.7 1.7 0 0 0 1.88-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9c.2.35.4.7.6 1h.1a2 2 0 1 1 0 4H20a1.7 1.7 0 0 0-.6 1Z"/></svg>',
        upload: '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/></svg>',
        download: '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></svg>',
        rocket: '<svg viewBox="0 0 24 24"><path d="M5 15c-1.2 1-2 2.8-2 5 2.2 0 4-.8 5-2"/><path d="M9 15 4 10l4-2 3 3"/><path d="m14 10 3 3-2 4-5-5"/><path d="M14 4c2.3-1 4.7-1 7 0 0 2.3-.3 5-2 7l-8 8-6-6 8-8c.3-.3.6-.7 1-1Z"/><circle cx="16" cy="8" r="1.5"/></svg>',
        shield: '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>',
        globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 0 20"/><path d="M12 2a15.3 15.3 0 0 0 0 20"/></svg>',
        refresh: '<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.5 6.3L3 16"/><path d="M3 16h6v6"/><path d="M3 12A9 9 0 0 1 18.5 5.7L21 8"/><path d="M21 8h-6V2"/></svg>',
        copy: '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
        external: '<svg viewBox="0 0 24 24"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
        key: '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="14.5" r="5.5"/><path d="m12 10 8-8"/><path d="m16 6 2 2"/><path d="m18 4 2 2"/></svg>',
        book: '<svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15Z"/></svg>',
        arrowLeft: '<svg viewBox="0 0 24 24"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg>',
        login: '<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
    };
    return `<span class="ui-icon" aria-hidden="true">${icons[name] || icons.folder}</span>`;
}

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
            const isPublic = root.public !== false;
            permissionsStore[key] = {
                type: 'mega',
                index: index,
                id: root.id || root.name,
                name: root.name,
                public: isPublic,
                auth: isPublic ? null : (root.auth || {})
            };
        });
    }

    return permissionsStore;
}

// Dashboard HTML Template
function getDashboardHTML(permissions, message = '') {
    const bootswatchTheme = normalizeTheme(uiConfig.theme);
    const themeOptions = (uiConfig.available_themes || ['slate', 'dark']).map(theme =>
        `<option value="${theme}" ${uiConfig.theme === theme ? 'selected' : ''}>${theme}</option>`
    ).join('');
    const playerOptions = (uiConfig.available_players || ['plyr', 'jwplayer']).map(player =>
        `<option value="${player}" ${uiConfig.default_player === player ? 'selected' : ''}>${player}</option>`
    ).join('');
    const permissionRows = Object.entries(permissions).map(([key, perm]) => {
        const typeIcon = perm.type === 'google_drive' ? icon('folder') : icon('cloud');
        const typeBadge = perm.type === 'google_drive' ? 
            '<span class="badge bg-primary">Google Drive</span>' : 
            '<span class="badge bg-info">Mega.nz</span>';
        const accessBadge = perm.public ? 
            '<span class="badge bg-success">Public</span>' : 
            '<span class="badge bg-warning">Auth Required</span>';
        
        return `
        <tr>
            <td><span class="cell-title">${typeIcon}<span>${perm.name}</span></span></td>
            <td>${typeBadge}</td>
            <td>${accessBadge}</td>
            <td>
                <code>${perm.id}</code>
            </td>
            <td class="table-actions">
                <button class="btn btn-sm btn-outline-primary action-btn" onclick="editPermission('${key}')">
                    Edit
                </button>
                <button class="btn btn-sm btn-outline-${perm.public ? 'warning' : 'success'} action-btn" 
                    onclick="toggleAccess('${key}')">
                    ${perm.public ? 'Make Private' : 'Make Public'}
                </button>
            </td>
        </tr>`;
    }).join('');
    const megaAccountRows = (megaConfig.accounts || []).map((account, index) => `
        <tr>
            <td><code>${index}</code></td>
            <td>${escapeHTML(account.email || '')}</td>
            <td><span class="badge bg-success">Configured</span></td>
            <td class="table-actions">
                <form action="/dashboard/mega-account-remove" method="POST" onsubmit="return confirm('Remove this MEGA account from the pool?')" class="d-inline">
                    <input type="hidden" name="index" value="${index}">
                    <button class="btn btn-sm btn-outline-danger" type="submit">Remove</button>
                </form>
            </td>
        </tr>
    `).join('');
    const passwordRuleRows = (pathPasswordConfig.rules || []).map((rule, index) => `
        <tr>
            <td><code>${escapeHTML(rule.drive_type || 'google')}</code></td>
            <td><code>${escapeHTML(rule.drive_index ?? 0)}</code></td>
            <td><code>${escapeHTML(rule.path || '/')}</code></td>
            <td>${escapeHTML(rule.label || '')}</td>
            <td class="table-actions">
                <form action="/dashboard/path-password-remove" method="POST" onsubmit="return confirm('Remove this password rule?')" class="d-inline">
                    <input type="hidden" name="index" value="${index}">
                    <button class="btn btn-sm btn-outline-danger" type="submit">Remove</button>
                </form>
            </td>
        </tr>
    `).join('');

    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - ${authConfig.siteName}</title>
    <link rel="icon" href="${uiConfig.favicon}">
    <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.0.0/dist/${bootswatchTheme}/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --surface-shadow: 0 12px 34px rgba(15, 23, 42, 0.12);
            --panel-radius: 8px;
            --icon-size: 1.05rem;
        }
        body { padding-top: 72px; }
        .navbar { box-shadow: 0 10px 30px rgba(0,0,0,0.16); }
        .navbar-brand { font-weight: 700; max-width: 64vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .dashboard-header { 
            background:
                radial-gradient(circle at 10% 20%, rgba(56, 189, 248, .22), transparent 26%),
                linear-gradient(135deg, #0f172a 0%, #14532d 48%, #111827 100%);
            color: white;
            padding: 32px 0;
            margin-bottom: 24px;
        }
        .dashboard-title { display: flex; gap: 12px; align-items: center; margin: 0; font-size: clamp(1.65rem, 3vw, 2.4rem); }
        .dashboard-title .ui-icon { width: 2rem; height: 2rem; }
        .dashboard-shell { max-width: 1320px; }
        .card { margin-bottom: 20px; border-radius: var(--panel-radius); box-shadow: var(--surface-shadow); overflow: hidden; }
        .card-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
        .section-title { display: inline-flex; align-items: center; gap: 10px; }
        .section-title .ui-icon { color: var(--bs-primary); }
        .stats-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 20px; }
        .stats-card { text-align: left; padding: 18px; min-height: 112px; display: flex; flex-direction: column; justify-content: space-between; }
        .stats-label { font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; opacity: .82; }
        .stats-number { font-size: clamp(2rem, 4vw, 2.7rem); line-height: 1; font-weight: 800; }
        .table-responsive { border-radius: 8px; overflow-x: auto; }
        .table { margin-bottom: 0; vertical-align: middle; }
        .table code { white-space: nowrap; }
        .cell-title { display: inline-flex; align-items: center; gap: 10px; min-width: 180px; font-weight: 600; }
        .table-actions { min-width: 180px; }
        .action-btn { margin: 2px 4px 2px 0; }
        .modal-header { background: #f8f9fa; }
        .permission-key { font-family: monospace; font-size: 0.85rem; }
        .ui-icon { display: inline-flex; width: var(--icon-size); height: var(--icon-size); flex: 0 0 auto; vertical-align: -0.18em; }
        .ui-icon svg { width: 100%; height: 100%; fill: none; stroke: currentColor; stroke-width: 1.9; stroke-linecap: round; stroke-linejoin: round; }
        .btn .ui-icon, a .ui-icon { margin-right: 6px; }
        .quick-actions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
        .quick-actions .btn { min-height: 44px; }
        .tool-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
        .settings-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; align-items: end; }
        .settings-grid .wide { grid-column: span 2; }
        .settings-grid .full { grid-column: 1 / -1; }
        .api-example { white-space: pre-wrap; word-break: break-word; }
        .subsection-label { margin: 10px 0 0; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; color: var(--bs-secondary-color); }
        .link-list { display: grid; gap: 10px; }
        .link-list a { display: inline-flex; align-items: center; gap: 8px; text-decoration: none; }
        pre { max-height: 220px; overflow: auto; }
        @media (max-width: 991.98px) {
            body { padding-top: 64px; }
            .dashboard-header { padding: 24px 0; }
            .stats-grid, .settings-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .quick-actions, .tool-actions { grid-template-columns: 1fr; }
        }
        @media (max-width: 575.98px) {
            .dashboard-shell { padding-left: 12px; padding-right: 12px; }
            .stats-grid, .settings-grid { grid-template-columns: 1fr; }
            .settings-grid .wide { grid-column: auto; }
            .card-body, .card-header { padding: 14px; }
            .table-actions { min-width: 150px; }
            .modal-dialog { margin: .75rem; }
            .login-card { padding: 24px !important; }
        }
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
            <h1 class="dashboard-title">${icon('dashboard')}<span>Permission Dashboard</span></h1>
            <p class="mb-0">Manage access permissions for your folders and files</p>
        </div>
    </div>

    <div class="container dashboard-shell">
        ${message ? `<div class="alert alert-success alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>` : ''}

        <!-- Stats Cards -->
        <div class="stats-grid">
                <div class="card stats-card bg-primary text-white">
                    <div class="stats-number">${authConfig.roots.length}</div>
                    <div class="stats-label">Google Drives</div>
                </div>
                <div class="card stats-card bg-info text-white">
                    <div class="stats-number">${megaConfig.roots ? megaConfig.roots.length : 0}</div>
                    <div class="stats-label">Mega.nz Folders</div>
                </div>
                <div class="card stats-card bg-success text-white">
                    <div class="stats-number">${Object.values(permissions).filter(p => p.public).length}</div>
                    <div class="stats-label">Public Access</div>
                </div>
                <div class="card stats-card bg-warning text-dark">
                    <div class="stats-number">${Object.values(permissions).filter(p => !p.public).length}</div>
                    <div class="stats-label">Auth Required</div>
                </div>
        </div>

        <!-- Permissions Table -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0 section-title">${icon('folder')}<span>Folder Permissions</span></h5>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addFolderModal">
                    Add Folder
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

        <!-- UI and Ad Gate Settings -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('settings')}<span>Interface & Link Gate</span></h5>
            </div>
            <div class="card-body">
                <form action="/dashboard/settings" method="POST" class="settings-grid">
                    <div class="full subsection-label">Interface</div>
                    <div>
                        <label class="form-label">Theme</label>
                        <select name="theme" class="form-select">${themeOptions}</select>
                    </div>
                    <div>
                        <label class="form-label">Default Player</label>
                        <select name="default_player" class="form-select">${playerOptions}</select>
                    </div>
                    <div class="wide">
                        <label class="form-label">JWPlayer Script</label>
                        <input type="url" name="jwplayer_script" class="form-control" value="${escapeHTML(uiConfig.jwplayer_script || '')}" placeholder="https://cdn.jwplayer.com/libraries/KB5zFt7A.js">
                    </div>
                    <div class="wide">
                        <label class="form-label">GPLinks API Token</label>
                        <input type="password" name="api_token" class="form-control" value="${adConfig.api_token || ''}" autocomplete="off">
                    </div>
                    <div class="wide">
                        <label class="form-label">Allowed Return Referers</label>
                        <input type="text" name="allowed_return_referers" class="form-control" value="${(adConfig.allowed_return_referers || []).join(', ')}" placeholder="gplinks.com, gplinks.in">
                    </div>
                    <div>
                        <label class="form-label">Wait Seconds</label>
                        <input type="number" min="0" name="min_wait_seconds" class="form-control" value="${adConfig.min_wait_seconds}">
                    </div>
                    <div>
                        <label class="form-label">View Expiry Seconds</label>
                        <input type="number" min="60" name="view_expiry_seconds" class="form-control" value="${adConfig.view_expiry_seconds}">
                    </div>
                    <div>
                        <label class="form-label">Download Expiry Seconds</label>
                        <input type="number" min="60" name="download_expiry_seconds" class="form-control" value="${adConfig.download_expiry_seconds}">
                    </div>
                    <div>
                        <div class="form-check form-switch pb-2">
                            <input class="form-check-input" type="checkbox" name="ad_enabled" id="adEnabled" ${adConfig.enabled ? 'checked' : ''}>
                            <label class="form-check-label" for="adEnabled">Enable ad shortener</label>
                        </div>
                    </div>
                    <div>
                        <div class="form-check form-switch pb-2">
                            <input class="form-check-input" type="checkbox" name="require_return_referer" id="requireReturnReferer" ${adConfig.require_return_referer ? 'checked' : ''}>
                            <label class="form-check-label" for="requireReturnReferer">Require return referer</label>
                        </div>
                    </div>
                    <div class="full subsection-label">Browserless and Upload</div>
                    <div class="wide">
                        <label class="form-label">Browserless Endpoint</label>
                        <input type="url" name="browserless_endpoint" class="form-control" value="${browserlessConfig.endpoint || ''}" placeholder="https://production-sfo.browserless.io">
                    </div>
                    <div class="wide">
                        <label class="form-label">Browserless API Token</label>
                        <input type="password" name="browserless_api_token" class="form-control" value="${browserlessConfig.api_token || ''}" autocomplete="off">
                    </div>
                    <div>
                        <label class="form-label">Browserless Timeout</label>
                        <input type="number" min="30" name="browserless_timeout_seconds" class="form-control" value="${browserlessConfig.timeout_seconds}">
                    </div>
                    <div>
                        <label class="form-label">Max Upload MB</label>
                        <input type="number" min="1" name="max_upload_mb" class="form-control" value="${megaUploadConfig.max_upload_mb}">
                    </div>
                    <div>
                        <label class="form-label">Pool Name</label>
                        <input type="text" name="mega_pool_name" class="form-control" value="${megaUploadConfig.pool_name || 'Mega Pool'}">
                    </div>
                    <div>
                        <label class="form-label">Upload Target</label>
                        <select name="target_strategy" class="form-select">
                            <option value="round_robin" ${megaUploadConfig.target_strategy === 'round_robin' ? 'selected' : ''}>Round Robin</option>
                            <option value="first" ${megaUploadConfig.target_strategy === 'first' ? 'selected' : ''}>First Account</option>
                        </select>
                    </div>
                    <div>
                        <div class="form-check form-switch pb-2">
                            <input class="form-check-input" type="checkbox" name="browserless_enabled" id="browserlessEnabled" ${browserlessConfig.enabled ? 'checked' : ''}>
                            <label class="form-check-label" for="browserlessEnabled">Enable Browserless</label>
                        </div>
                    </div>
                    <div>
                        <div class="form-check form-switch pb-2">
                            <input class="form-check-input" type="checkbox" name="mega_upload_enabled" id="megaUploadEnabled" ${megaUploadConfig.enabled ? 'checked' : ''}>
                            <label class="form-check-label" for="megaUploadEnabled">Enable admin uploads</label>
                        </div>
                    </div>
                    <div>
                        <div class="form-check form-switch pb-2">
                            <input class="form-check-input" type="checkbox" name="allow_automated_account_creation" id="allowAutomatedAccountCreation" ${megaUploadConfig.allow_automated_account_creation ? 'checked' : ''}>
                            <label class="form-check-label" for="allowAutomatedAccountCreation">Allow automated MEGA account creation</label>
                        </div>
                    </div>
                    <div>
                        <button type="submit" class="btn btn-primary w-100">Save Settings</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Mega Pool Tools (Enhanced) -->
        <div class="card" id="megaPoolTools">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('cloud')}<span>Mega Pool Tools</span></h5>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline-primary btn-sm" type="button" onclick="testBrowserless()">
                        ${icon('external')}Test Browserless
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" type="button" onclick="showUploadStatus()">
                        ${icon('upload')}Pool Status
                    </button>
                    <button class="btn btn-outline-info btn-sm" type="button" onclick="refreshFolderTree()">
                        ${icon('refresh')}Refresh Folders
                    </button>
                </div>
            </div>
            <div class="card-body">
                <style>
                    .mega-pool-grid { display: grid; grid-template-columns: 280px 1fr; gap: 20px; }
                    @media (max-width: 991.98px) { .mega-pool-grid { grid-template-columns: 1fr; } }
                    .folder-tree { max-height: 420px; overflow-y: auto; border: 1px solid var(--bs-border-color, #444); border-radius: 6px; padding: 10px; font-size: .88rem; }
                    .folder-tree-node { cursor: pointer; padding: 3px 6px; border-radius: 4px; display: flex; align-items: center; gap: 6px; user-select: none; }
                    .folder-tree-node:hover { background: rgba(var(--bs-primary-rgb, 13,110,253), .12); }
                    .folder-tree-node.active { background: rgba(var(--bs-primary-rgb, 13,110,253), .22); font-weight: 600; }
                    .folder-tree-toggle { width: 16px; text-align: center; font-size: .72rem; opacity: .7; flex-shrink: 0; }
                    .folder-tree-children { margin-left: 18px; }
                    .folder-tree-empty { color: var(--bs-secondary-color); font-style: italic; padding: 8px; }
                    .drop-zone { border: 2px dashed var(--bs-border-color, #555); border-radius: 8px; padding: 28px 16px; text-align: center; transition: all .2s; cursor: pointer; position: relative; }
                    .drop-zone:hover, .drop-zone.drag-over { border-color: var(--bs-primary); background: rgba(var(--bs-primary-rgb, 13,110,253), .06); }
                    .drop-zone.drag-over { transform: scale(1.01); }
                    .drop-zone-icon { font-size: 2.4rem; opacity: .5; margin-bottom: 6px; }
                    .drop-zone input[type="file"] { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
                    .upload-queue { max-height: 260px; overflow-y: auto; }
                    .upload-item { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--bs-border-color, #333); }
                    .upload-item:last-child { border-bottom: none; }
                    .upload-item-name { flex: 1; font-size: .85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    .upload-item-size { font-size: .78rem; opacity: .7; white-space: nowrap; }
                    .upload-item-status { font-size: .78rem; min-width: 70px; text-align: right; }
                    .upload-progress { height: 6px; border-radius: 3px; background: var(--bs-border-color, #444); overflow: hidden; margin-top: 2px; }
                    .upload-progress-bar { height: 100%; background: linear-gradient(90deg, #22c55e, #34d399); border-radius: 3px; transition: width .3s ease; }
                    .upload-progress-bar.error { background: linear-gradient(90deg, #ef4444, #f87171); }
                    .mirror-badge { font-size: .72rem; padding: 2px 8px; }
                    .account-pills { display: flex; flex-wrap: wrap; gap: 6px; }
                    .account-pill { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 20px; font-size: .78rem; background: rgba(var(--bs-success-rgb, 25,135,84), .15); border: 1px solid rgba(var(--bs-success-rgb, 25,135,84), .3); }
                    .account-pill .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--bs-success); flex-shrink: 0; }
                    .batch-textarea { min-height: 60px; font-family: monospace; font-size: .85rem; }
                </style>

                <!-- Account Pool Status -->
                <div class="account-pills mb-3" id="accountPills" aria-live="polite">
                    ${(megaConfig.accounts || []).map((acc, i) => `
                        <span class="account-pill"><span class="dot"></span>${escapeHTML(acc.email)}</span>
                    `).join('') || '<span class="text-muted">No pool accounts configured</span>'}
                </div>

                <div class="mega-pool-grid">
                    <!-- Left: Folder Browser -->
                    <div>
                        <h6 class="mb-2">${icon('folder')} Folder Browser</h6>
                        <div class="folder-tree" id="folderTree">
                            <div class="folder-tree-empty">Loading folders...</div>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">Selected: <code id="selectedFolderPath">/</code></small>
                        </div>
                    </div>

                    <!-- Right: Upload & Create -->
                    <div>
                        <div class="mb-3">
                            <label class="form-label form-label-sm mb-1" for="megaTargetAccount">Upload / folder account</label>
                            <select class="form-select form-select-sm" id="megaTargetAccount">
                                <option value="">Mega Pool — automatic (${escapeHTML(megaUploadConfig.target_strategy || 'round_robin')})</option>
                                ${(megaConfig.accounts || []).map((account, index) => `<option value="${index}">${escapeHTML(account.email || `MEGA Account ${index + 1}`)}</option>`).join('')}
                            </select>
                            <small class="text-muted">Choose an account before creating a folder or uploading. Pool mode selects the next ready account.</small>
                        </div>
                        <!-- Batch Folder Creation -->
                        <h6 class="mb-2">${icon('folder')} Create Folders</h6>
                        <div class="row g-2 mb-3">
                            <div class="col-lg-5">
                                <input type="text" class="form-control form-control-sm" id="folderCreatePath" placeholder="Parent path" value="/">
                            </div>
                            <div class="col-lg-5">
                                <input type="text" class="form-control form-control-sm" id="folderCreateNames" placeholder="name1, name2, name3 (comma-separated)">
                            </div>
                            <div class="col-lg-2 d-flex gap-1">
                                <button class="btn btn-primary btn-sm flex-fill" onclick="batchCreateFolders(false)" title="Create on one account">${icon('folder')}Create</button>
                            </div>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="mirrorFolders">
                            <label class="form-check-label" for="mirrorFolders">
                                <span class="badge bg-info mirror-badge">MIRROR</span> Create folders on ALL pool accounts
                            </label>
                        </div>

                        <hr>

                        <!-- Multi-File Upload -->
                        <h6 class="mb-2">${icon('upload')} Upload Files</h6>
                        <div class="drop-zone" id="dropZone">
                            <input type="file" id="fileInput" multiple>
                            <div class="drop-zone-icon">📁</div>
                            <div>Drop files here or <strong>click to browse</strong></div>
                            <small class="text-muted">Multiple files supported • Max ${megaUploadConfig.max_upload_mb || 2000} MB each</small>
                        </div>

                        <div class="form-check form-switch mt-2 mb-2">
                            <input class="form-check-input" type="checkbox" id="mirrorUpload">
                            <label class="form-check-label" for="mirrorUpload">
                                <span class="badge bg-warning text-dark mirror-badge">MIRROR</span> Upload to ALL pool accounts simultaneously
                            </label>
                        </div>

                        <!-- Upload Queue -->
                        <div class="upload-queue mt-2" id="uploadQueue"></div>

                        <!-- Upload Controls -->
                        <div class="d-flex gap-2 mt-2" id="uploadControls" style="display:none!important">
                            <button class="btn btn-success btn-sm flex-fill" id="btnStartUpload" onclick="startUploadQueue()">
                                ${icon('upload')} Start Upload
                            </button>
                            <button class="btn btn-outline-danger btn-sm" onclick="clearUploadQueue()">Clear</button>
                        </div>

                        <!-- Overall Progress -->
                        <div id="overallProgress" class="mt-2" style="display:none">
                            <div class="d-flex justify-content-between">
                                <small id="overallProgressLabel">Uploading...</small>
                                <small id="overallProgressPct">0%</small>
                            </div>
                            <div class="upload-progress" style="height:8px">
                                <div class="upload-progress-bar" id="overallProgressBar" style="width:0%"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="alert alert-secondary mt-3 mb-0">
                    <strong>${megaUploadConfig.pool_name || 'Mega Pool'}</strong> — ${(megaConfig.accounts || []).length} account(s) pooled.
                    Strategy: <code>${megaUploadConfig.target_strategy}</code> | Chunk size: <code>8 MB</code>
                    ${browserlessConfig.enabled && megaUploadConfig.allow_automated_account_creation ? `
                        <button class="btn btn-outline-info btn-sm float-end" type="button" id="btnGenAccount" onclick="createAutomatedAccount(this)">
                            ${icon('bolt')}Generate Pool Account
                        </button>
                    ` : '<span class="text-muted float-end">Auto account creation disabled.</span>'}
                </div>
            </div>
        </div>

        <!-- Upload API and MEGA Account Pool -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('upload')}<span>Upload API & Account Pool</span></h5>
            </div>
            <div class="card-body">
                <div class="row g-4">
                    <div class="col-lg-6">
                        <h6>Add MEGA Account</h6>
                        <form action="/dashboard/mega-account-add" method="POST" class="row g-2">
                            <div class="col-md-5">
                                <input type="email" name="email" class="form-control" placeholder="mega@email.com" required>
                            </div>
                            <div class="col-md-5">
                                <input type="password" name="password" class="form-control" placeholder="Password" required>
                            </div>
                            <div class="col-md-2">
                                <button class="btn btn-primary w-100" type="submit">Add</button>
                            </div>
                        </form>
                        <div class="table-responsive mt-3">
                            <table class="table table-sm table-hover">
                                <thead><tr><th>#</th><th>Email</th><th>Status</th><th>Action</th></tr></thead>
                                <tbody>${megaAccountRows || '<tr><td colspan="4" class="text-muted">No MEGA accounts configured.</td></tr>'}</tbody>
                            </table>
                        </div>
                    </div>
                    <div class="col-lg-6">
                        <h6>curl Upload Examples</h6>
                        <pre class="bg-dark text-light p-3 rounded api-example"><code>curl -u '${dashboardConfig.admin_username}:YOUR_PASSWORD' -F 'target=mega_pool' -F 'path=/' -F 'file=@video.mp4' '${'/api/upload'}'

curl -u '${dashboardConfig.admin_username}:YOUR_PASSWORD' -F 'target=drive' -F 'drive_index=0' -F 'path=/' -F 'file=@video.mp4' '${'/api/upload'}'

curl -u '${dashboardConfig.admin_username}:YOUR_PASSWORD' -F 'target=mega' -F 'drive_index=0' -F 'path=/Movies/' -F 'file=@video.mp4' '${'/api/upload'}'</code></pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- Path Password Rules -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('shield')}<span>Path Password Protection</span></h5>
            </div>
            <div class="card-body">
                <form action="/dashboard/path-password-add" method="POST" class="row g-3">
                    <div class="col-lg-2 col-md-4">
                        <label class="form-label">Drive Type</label>
                        <select name="drive_type" class="form-select">
                            <option value="google">Google</option>
                            <option value="mega">MEGA</option>
                        </select>
                    </div>
                    <div class="col-lg-2 col-md-4">
                        <label class="form-label">Drive Index</label>
                        <input type="number" min="0" name="drive_index" class="form-control" value="0">
                    </div>
                    <div class="col-lg-3 col-md-4">
                        <label class="form-label">Path</label>
                        <input type="text" name="path" class="form-control" placeholder="/myfolder/hello/" required>
                    </div>
                    <div class="col-lg-2 col-md-6">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <div class="col-lg-2 col-md-6">
                        <label class="form-label">Label</label>
                        <input type="text" name="label" class="form-control" placeholder="Hello folder">
                    </div>
                    <div class="col-lg-1 col-md-12 d-flex align-items-end">
                        <button class="btn btn-primary w-100" type="submit">Add</button>
                    </div>
                </form>
                <div class="table-responsive mt-3">
                    <table class="table table-sm table-hover">
                        <thead><tr><th>Type</th><th>Index</th><th>Path</th><th>Label</th><th>Action</th></tr></thead>
                        <tbody>${passwordRuleRows || '<tr><td colspan="5" class="text-muted">No path password rules configured.</td></tr>'}</tbody>
                    </table>
                </div>
                <p class="text-muted mb-0">Rules apply to the exact folder subtree only. A rule for <code>/myfolder/hello/</code> does not protect <code>/myfolder/</code> or <code>/myfolder/hello2/</code>.</p>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('bolt')}<span>Quick Actions</span></h5>
            </div>
            <div class="card-body">
                <div class="quick-actions">
                    <button class="btn btn-outline-success w-100" onclick="makeAllPublic()">
                        ${icon('globe')}Make All Public
                    </button>
                    <button class="btn btn-outline-warning w-100" onclick="makeAllPrivate()">
                        ${icon('shield')}Make All Private
                    </button>
                    <button class="btn btn-outline-info w-100" onclick="refreshPermissions()">
                        ${icon('refresh')}Refresh Permissions
                    </button>
                </div>
            </div>
        </div>

        <!-- Add User Section -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 section-title">${icon('users')}<span>Manage Users</span></h5>
            </div>
            <div class="card-body">
                <form action="/dashboard/add-user" method="POST" class="row g-3">
                    <div class="col-lg-3 col-md-6">
                        <select name="folder" class="form-select" required>
                            <option value="">Select Folder...</option>
                            ${Object.entries(permissions).map(([key, perm]) => 
                                `<option value="${key}">${perm.name}</option>`
                            ).join('')}
                        </select>
                    </div>
                    <div class="col-lg-3 col-md-6">
                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="col-lg-3 col-md-6">
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <div class="col-lg-3 col-md-6">
                        <button type="submit" class="btn btn-primary w-100">Add User</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Rclone Import/Export Section -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0 section-title">${icon('settings')}<span>Rclone Configuration</span></h5>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline-primary btn-sm" data-bs-toggle="modal" data-bs-target="#rcloneImportModal">
                        ${icon('upload')}Import
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="exportRclone()">
                        ${icon('download')}Export
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
                <h5 class="mb-0 section-title">${icon('rocket')}<span>Deployment Info</span></h5>
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
                        <ul class="list-unstyled link-list">
                            <li><a href="https://dash.cloudflare.com/" target="_blank">${icon('cloud')}Cloudflare Dashboard</a></li>
                            <li><a href="https://developers.cloudflare.com/workers/" target="_blank">${icon('book')}Workers Docs</a></li>
                            <li><a href="https://console.cloud.google.com/" target="_blank">${icon('key')}Google Cloud Console</a></li>
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
                    <h5 class="modal-title section-title">${icon('upload')}<span>Import Rclone Configuration</span></h5>
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
                    <h5 class="modal-title section-title">${icon('download')}<span>Export Rclone Configuration</span></h5>
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
                        ${icon('copy')}Copy to Clipboard
                    </button>
                    <button type="button" class="btn btn-success" onclick="downloadRcloneConfig()">
                        ${icon('download')}Download
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

        function testBrowserless() {
            fetch('/dashboard/browserless-test', { method: 'POST' })
                .then(r => r.json())
                .then(result => {
                    alert(result.success ? 'Browserless test passed: ' + result.title : 'Browserless test failed: ' + result.error);
                })
                .catch(e => alert('Browserless test failed: ' + e.message));
        }

        function showUploadStatus() {
            fetch('/dashboard/mega-upload-status')
                .then(r => r.json())
                .then(result => {
                    alert(result.enabled ? result.message : 'Upload is disabled: ' + result.message);
                })
                .catch(e => alert('Upload status failed: ' + e.message));
        }

        function formatStorage(bytes) {
            return formatBytes(Number(bytes || 0));
        }

        function refreshMegaPoolStatus() {
            fetch('/dashboard/mega-upload-status')
                .then(r => r.json())
                .then(result => {
                    const pills = document.getElementById('accountPills');
                    if (!pills || !Array.isArray(result.accounts)) return;
                    const pool = result.pool_storage || {};
                    const poolLabel = result.accounts.length
                        ? '<span class="account-pill"><span class="dot"></span>Pool free: ' + formatStorage(pool.free) + ' / ' + formatStorage(pool.total) + '</span>'
                        : '';
                    pills.innerHTML = poolLabel + result.accounts.map(account => {
                        const detail = account.ready
                            ? formatStorage(account.free) + ' free / ' + formatStorage(account.total)
                            : 'unavailable';
                        return '<span class="account-pill" title="Used: ' + formatStorage(account.used) + '"><span class="dot"></span>' + account.email + ' — ' + detail + '</span>';
                    }).join('');
                })
                .catch(() => { /* Static account list remains visible if MEGA is temporarily unavailable. */ });
        }

        function createAutomatedAccount(btn) {
            if (!confirm('Are you sure you want to generate a new MEGA account using Browserless and add it to the pool? This can take up to 2 minutes.')) return;
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Generating...';
            
            fetch('/dashboard/mega-create-automated-account', { method: 'POST' })
            .then(r => r.json())
            .then(result => {
                btn.innerHTML = originalText;
                btn.disabled = false;
                if (result.success) {
                    alert('Success! Created account: ' + result.email + '\\nPassword: ' + result.password);
                    location.reload();
                } else {
                    alert('Error creating account: ' + result.error);
                }
            })
            .catch(e => {
                btn.innerHTML = originalText;
                btn.disabled = false;
                alert('Request failed: ' + e.message);
            });
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
                    alert('Configuration is valid.\\n\\nRemotes found: ' + 
                        result.remotes.map(r => r.name + ' (' + r.type + ')').join(', '));
                } else {
                    alert('Configuration errors:\\n' + result.errors.join('\\n'));
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
        // ===================== Mega Pool Tools JS =====================
        let selectedFolder = '/';
        let uploadFiles = [];
        let uploading = false;

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        // --- Folder Tree ---
        function refreshFolderTree() {
            const tree = document.getElementById('folderTree');
            tree.innerHTML = '<div class="folder-tree-empty">Loading...</div>';
            fetch('/dashboard/mega-pool-browse')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) { tree.innerHTML = '<div class="folder-tree-empty">' + (data.error || 'No folders') + '</div>'; return; }
                    tree.innerHTML = '';
                    // Root node
                    const rootNode = document.createElement('div');
                    rootNode.className = 'folder-tree-node active';
                    rootNode.innerHTML = '<span class="folder-tree-toggle"></span>📂 / (root)';
                    rootNode.onclick = () => selectTreeFolder('/', rootNode);
                    tree.appendChild(rootNode);
                    renderFolderNodes(tree, data.folders || [], '');
                })
                .catch(e => { tree.innerHTML = '<div class="folder-tree-empty">Error: ' + e.message + '</div>'; });
        }

        function renderFolderNodes(container, folders, indent) {
            for (const folder of folders) {
                const wrapper = document.createElement('div');
                wrapper.className = 'folder-tree-children';
                const node = document.createElement('div');
                node.className = 'folder-tree-node';
                const hasChildren = folder.children && folder.children.length > 0;
                node.innerHTML = '<span class="folder-tree-toggle">' + (hasChildren ? '▶' : '') + '</span>📁 ' + folder.name;
                node.onclick = (e) => {
                    e.stopPropagation();
                    selectTreeFolder(folder.path, node);
                    if (hasChildren) {
                        const children = wrapper.querySelector('.folder-tree-children');
                        if (children) {
                            children.style.display = children.style.display === 'none' ? 'block' : 'none';
                            const toggle = node.querySelector('.folder-tree-toggle');
                            toggle.textContent = children.style.display === 'none' ? '▶' : '▼';
                        }
                    }
                };
                wrapper.appendChild(node);
                if (hasChildren) {
                    const childContainer = document.createElement('div');
                    childContainer.className = 'folder-tree-children';
                    renderFolderNodes(childContainer, folder.children, indent + '  ');
                    wrapper.appendChild(childContainer);
                }
                container.appendChild(wrapper);
            }
        }

        function selectTreeFolder(path, nodeEl) {
            selectedFolder = path;
            document.getElementById('selectedFolderPath').textContent = path;
            document.getElementById('folderCreatePath').value = path;
            document.querySelectorAll('.folder-tree-node').forEach(n => n.classList.remove('active'));
            if (nodeEl) nodeEl.classList.add('active');
        }

        // --- Drag and Drop Upload ---
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        if (dropZone) {
            ['dragenter', 'dragover'].forEach(evt => dropZone.addEventListener(evt, e => {
                e.preventDefault(); dropZone.classList.add('drag-over');
            }));
            ['dragleave', 'drop'].forEach(evt => dropZone.addEventListener(evt, e => {
                e.preventDefault(); dropZone.classList.remove('drag-over');
            }));
            dropZone.addEventListener('drop', e => {
                const files = Array.from(e.dataTransfer.files);
                addFilesToQueue(files);
            });
        }
        if (fileInput) {
            fileInput.addEventListener('change', () => {
                addFilesToQueue(Array.from(fileInput.files));
                fileInput.value = '';
            });
        }

        function addFilesToQueue(files) {
            for (const f of files) {
                uploadFiles.push({ file: f, status: 'pending', progress: 0, result: null, error: null });
            }
            renderUploadQueue();
        }

        function renderUploadQueue() {
            const queue = document.getElementById('uploadQueue');
            const controls = document.getElementById('uploadControls');
            if (!uploadFiles.length) {
                queue.innerHTML = '';
                controls.style.display = 'none';
                controls.style.cssText = 'display:none!important';
                return;
            }
            controls.style.cssText = '';
            controls.style.display = 'flex';
            queue.innerHTML = uploadFiles.map((item, i) => {
                const statusBadge = item.status === 'done' ? '<span class="badge bg-success">Done</span>'
                    : item.status === 'error' ? '<span class="badge bg-danger" title="' + (item.error || '') + '">Error</span>'
                    : item.status === 'uploading' ? '<span class="badge bg-primary">Uploading</span>'
                    : '<span class="badge bg-secondary">Pending</span>';
                const progressWidth = item.status === 'done' ? 100 : item.progress;
                const barClass = item.status === 'error' ? 'upload-progress-bar error' : 'upload-progress-bar';
                return '<div class="upload-item" id="upload-item-' + i + '">' +
                    '<span class="upload-item-name" title="' + item.file.name + '">' + item.file.name + '</span>' +
                    '<span class="upload-item-size">' + formatBytes(item.file.size) + '</span>' +
                    '<span class="upload-item-status">' + statusBadge + '</span>' +
                    '</div>' +
                    '<div class="upload-progress"><div class="' + barClass + '" id="upload-bar-' + i + '" style="width:' + progressWidth + '%"></div></div>';
            }).join('');
        }

        function clearUploadQueue() {
            if (uploading) { alert('Upload in progress. Please wait.'); return; }
            uploadFiles = [];
            renderUploadQueue();
            document.getElementById('overallProgress').style.display = 'none';
        }

        // --- Upload execution ---
        async function startUploadQueue() {
            if (uploading || !uploadFiles.length) return;
            uploading = true;
            const btn = document.getElementById('btnStartUpload');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Uploading...';
            document.getElementById('overallProgress').style.display = 'block';

            const mirror = document.getElementById('mirrorUpload')?.checked || false;
            const pending = uploadFiles.filter(f => f.status === 'pending');
            let completed = 0;

            for (const item of pending) {
                item.status = 'uploading';
                renderUploadQueue();
                try {
                    const formData = new FormData();
                    formData.append('file', item.file);
                    formData.append('upload_path', selectedFolder);
                    formData.append('target', mirror ? 'mega_pool_mirror' : 'mega_pool');
                    if (!mirror) formData.append('account_index', document.getElementById('megaTargetAccount')?.value || '');

                    const resp = await fetch('/dashboard/mega-upload-ajax', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await resp.json();
                    if (result.success) {
                        item.status = 'done';
                        item.progress = 100;
                        item.result = result;
                    } else {
                        item.status = 'error';
                        item.error = result.error || 'Upload failed';
                    }
                } catch (e) {
                    item.status = 'error';
                    item.error = e.message;
                }
                completed++;
                const pct = Math.round((completed / pending.length) * 100);
                document.getElementById('overallProgressBar').style.width = pct + '%';
                document.getElementById('overallProgressPct').textContent = pct + '%';
                document.getElementById('overallProgressLabel').textContent = 'Uploaded ' + completed + '/' + pending.length + ' files';
                renderUploadQueue();
            }

            uploading = false;
            btn.disabled = false;
            btn.innerHTML = '${icon('upload')} Start Upload';
            const errors = uploadFiles.filter(f => f.status === 'error').length;
            document.getElementById('overallProgressLabel').textContent = errors > 0
                ? 'Done with ' + errors + ' error(s)'
                : 'All uploads complete!';
            refreshFolderTree();
        }

        // --- Batch Folder Creation ---
        async function batchCreateFolders(mirror) {
            const path = document.getElementById('folderCreatePath').value || '/';
            const names = document.getElementById('folderCreateNames').value;
            if (!names.trim()) { alert('Enter at least one folder name.'); return; }
            const folderNames = names.split(',').map(n => n.trim()).filter(Boolean);
            if (!folderNames.length) { alert('Enter at least one folder name.'); return; }

            const mirrorChecked = document.getElementById('mirrorFolders')?.checked || false;
            const results = [];
            for (const name of folderNames) {
                try {
                    const formData = new FormData();
                    formData.append('parent_path', path);
                    formData.append('folder_name', name);
                    formData.append('mirror', mirrorChecked ? 'true' : 'false');
                    if (!mirrorChecked) formData.append('account_index', document.getElementById('megaTargetAccount')?.value || '');
                    const resp = await fetch('/dashboard/mega-create-folder-ajax', {
                        method: 'POST',
                        body: formData
                    });
                    const r = await resp.json();
                    results.push(r.success ? '✅ ' + name : '❌ ' + name + ': ' + (r.error || 'failed'));
                } catch (e) {
                    results.push('❌ ' + name + ': ' + e.message);
                }
            }
            alert('Folder Creation Results:\\n' + results.join('\\n'));
            document.getElementById('folderCreateNames').value = '';
            refreshFolderTree();
        }

        // Auto-load folder tree on page load
        if (document.getElementById('folderTree')) {
            setTimeout(refreshFolderTree, 500);
            setTimeout(refreshMegaPoolStatus, 600);
        }
    </script>
</body>
</html>`;
}

async function ensureMegaUploadDrives(megaDrives = []) {
    const accounts = megaConfig.accounts || [];
    if (!accounts.length) return megaDrives;

    const { MegaDrive } = await import('./megaDrive.js');
    const rootCount = megaConfig.roots?.length || 0;

    for (let i = 0; i < accounts.length; i++) {
        const account = accounts[i];
        const order = rootCount + i;
        const existing = megaDrives[order];
        if (existing && !existing.isPublicFolder && existing.masterKey && existing.sid) continue;

        const drive = new MegaDrive(megaConfig, order, {
            id: `account-${i}`,
            name: account.email || `MEGA Account ${i + 1}`,
            public: true
        }, account);
        await drive.init();
        megaDrives[order] = drive;
    }

    return megaDrives;
}

function selectReadyMegaUploadDrive(megaDrives = []) {
    const writable = megaDrives.filter(drive => drive && !drive.isPublicFolder && drive.masterKey && drive.sid);
    if (!writable.length) {
        throw new Error('No writable configured MEGA account roots are available.');
    }
    if (megaUploadConfig.target_strategy === 'first') {
        return writable[0];
    }
    const drive = writable[megaUploadCursor % writable.length];
    megaUploadCursor += 1;
    return drive;
}

async function selectMegaUploadDrive(megaDrives = []) {
    await ensureMegaUploadDrives(megaDrives);
    return selectReadyMegaUploadDrive(megaDrives);
}

async function selectMegaUploadTarget(megaDrives = [], accountIndex = '') {
    await ensureMegaUploadDrives(megaDrives);
    // Account indexes are stable config indexes, not the mixed public-root index.
    // This lets an admin choose the same account for folder creation and upload.
    if (accountIndex !== '' && accountIndex !== null && accountIndex !== undefined) {
        const index = Number(accountIndex);
        if (!Number.isInteger(index) || index < 0) throw new Error('Invalid MEGA account selection.');
        const order = (megaConfig.roots?.length || 0) + index;
        const drive = megaDrives[order];
        if (!drive || drive.isPublicFolder || !drive.masterKey || !drive.sid) {
            throw new Error('Selected MEGA account is not ready for uploads.');
        }
        return drive;
    }
    return selectReadyMegaUploadDrive(megaDrives);
}

// Dashboard Login Page
function getDashboardLoginHTML(error = '') {
    const bootswatchTheme = normalizeTheme(uiConfig.theme);
    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Login - ${authConfig.siteName}</title>
    <link rel="icon" href="${uiConfig.favicon}">
    <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.0.0/dist/${bootswatchTheme}/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --login-bg: #101827;
            --login-panel: #172033;
            --login-panel-border: rgba(148, 163, 184, .22);
            --login-text: #f8fafc;
            --login-muted: #cbd5e1;
            --login-link: #67e8f9;
        }
        body {
            background:
                radial-gradient(circle at 12% 18%, rgba(14, 165, 233, .28), transparent 28%),
                radial-gradient(circle at 84% 12%, rgba(34, 197, 94, .20), transparent 26%),
                linear-gradient(135deg, var(--login-bg) 0%, #0f2f24 52%, #111827 100%);
            color: var(--login-text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .login-card {
            background: var(--login-panel);
            border: 1px solid var(--login-panel-border);
            border-radius: 8px;
            padding: 34px;
            box-shadow: 0 18px 60px rgba(0,0,0,0.28);
            max-width: 420px;
            width: 100%;
        }
        .login-brand {
            display: flex;
            justify-content: center;
            margin-bottom: 18px;
        }
        .login-brand img { max-width: ${uiConfig.logo_width || '120px'}; height: auto; border-radius: 12px; }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h2 {
            color: var(--login-text);
            margin-bottom: 10px;
        }
        .login-header p {
            color: var(--login-muted);
        }
        .form-label { color: var(--login-text); }
        .login-home-link {
            color: var(--login-link);
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-weight: 600;
        }
        .login-home-link:hover, .login-home-link:focus {
            color: #a5f3fc;
        }
        .login-title { display: inline-flex; align-items: center; gap: 10px; }
        .ui-icon { display: inline-flex; width: 1.05rem; height: 1.05rem; flex: 0 0 auto; vertical-align: -0.18em; }
        .ui-icon svg { width: 100%; height: 100%; fill: none; stroke: currentColor; stroke-width: 1.9; stroke-linecap: round; stroke-linejoin: round; }
        a .ui-icon { margin-right: 6px; }
        @media (max-width: 575.98px) {
            body { padding: 16px; align-items: flex-start; }
            .login-card { padding: 24px; }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            ${uiConfig.logo_image ? `<div class="login-brand"><img src="${uiConfig.logo_link_name}" alt="${authConfig.siteName}"></div>` : ''}
            <h2 class="login-title">${icon('login')}<span>Dashboard Login</span></h2>
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
            <a href="/" class="login-home-link text-decoration-none">${icon('arrowLeft')}Back to Home</a>
        </div>
    </div>
</body>
</html>`;
}

// Helper to create disposable email using mail.tm
async function createMailTmAccount() {
    const domainsResp = await fetch('https://api.mail.tm/domains', {
        headers: { 'Accept': 'application/json' }
    });
    if (!domainsResp.ok) {
        const text = await domainsResp.text();
        throw new Error('Failed to get mail.tm domains (' + domainsResp.status + '): ' + (text || 'empty response'));
    }
    const domains = await domainsResp.json();
    const domain = (domains['hydra:member'] || domains)?.[0]?.domain;
    if (!domain) throw new Error('No mail.tm domains available');

    const user = 'mega' + Math.random().toString(36).substring(2, 12);
    const email = `${user}@${domain}`;
    const password = randomPassword(18);

    const createResp = await fetch('https://api.mail.tm/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ address: email, password })
    });
    if (!createResp.ok) {
        let detail;
        try { detail = JSON.stringify(await createResp.json()); } catch { detail = await createResp.text() || '(empty body)'; }
        throw new Error('Failed to create mail.tm account (' + createResp.status + '): ' + detail);
    }

    const tokenResp = await fetch('https://api.mail.tm/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ address: email, password })
    });
    if (!tokenResp.ok) {
        const text = await tokenResp.text();
        throw new Error('Failed to get mail.tm token (' + tokenResp.status + '): ' + (text || 'empty response'));
    }
    const tokenData = await tokenResp.json();
    return { email, password, token: tokenData.token };
}

async function isDashboardAuthenticated(request, env = {}) {
    return verifyDashboardSessionToken(getCookieValue(request, DASHBOARD_COOKIE_NAME), env);
}

async function getDashboardAuthCookie(url, authenticated, env = {}, username = '') {
    const secureAttr = url.protocol === 'https:' ? '; Secure' : '';
    const maxAge = authenticated ? DASHBOARD_SESSION_TTL_SECONDS : 0;
    const value = authenticated ? await createDashboardSessionToken(username, env) : '';

    return `${DASHBOARD_COOKIE_NAME}=${value}; Path=/dashboard; HttpOnly${secureAttr}; SameSite=Lax; Max-Age=${maxAge}`;
}

function isSameOriginDashboardMutation(request, url) {
    const method = request.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true;
    const fetchSite = request.headers.get('Sec-Fetch-Site');
    if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') return false;
    const origin = request.headers.get('Origin');
    return !origin || origin === url.origin;
}

// Dashboard Route Handler
async function handleDashboard(request, url, env = {}, megaDrives = []) {
    const path = url.pathname;
    const method = request.method;
    const isAuthenticated = await isDashboardAuthenticated(request, env);

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

        const admin = getAdminCredentials(env);
        if (username === admin.username && password === admin.password) {
            return new Response('', {
                status: 302,
                headers: {
                    'Location': '/dashboard',
                    'Set-Cookie': await getDashboardAuthCookie(url, true, env, admin.username)
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
                'Set-Cookie': await getDashboardAuthCookie(url, false, env)
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
    if (!isSameOriginDashboardMutation(request, url)) {
        return new Response('Forbidden', { status: 403 });
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
                await persistRuntimeSettings(env);
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

    // Update runtime UI and ad gate settings
    if (path === '/dashboard/settings' && method === 'POST') {
        try {
            const formData = await request.formData();
            const selectedTheme = formData.get('theme') || uiConfig.theme;
            const selectedPlayer = formData.get('default_player') || uiConfig.default_player;
            const availableThemes = uiConfig.available_themes || [];
            const availablePlayers = uiConfig.available_players || [];

            if (!availableThemes.includes(selectedTheme)) {
                throw new Error('Invalid theme selected.');
            }
            if (!availablePlayers.includes(selectedPlayer)) {
                throw new Error('Invalid player selected.');
            }

            uiConfig.theme = selectedTheme;
            uiConfig.default_player = selectedPlayer;
            uiConfig.jwplayer_script = String(formData.get('jwplayer_script') || '').trim() || 'https://cdn.jwplayer.com/libraries/KB5zFt7A.js';
            adConfig.enabled = formData.get('ad_enabled') === 'on';
            adConfig.api_token = formData.get('api_token') || '';
            adConfig.min_wait_seconds = Math.max(0, Number(formData.get('min_wait_seconds') || 10));
            adConfig.view_expiry_seconds = Math.max(60, Number(formData.get('view_expiry_seconds') || 600));
            adConfig.download_expiry_seconds = Math.max(60, Number(formData.get('download_expiry_seconds') || 1800));
            adConfig.require_return_referer = formData.get('require_return_referer') === 'on';
            adConfig.allowed_return_referers = String(formData.get('allowed_return_referers') || '')
                .split(',')
                .map(host => host.trim().toLowerCase())
                .filter(Boolean);

            browserlessConfig.enabled = formData.get('browserless_enabled') === 'on';
            browserlessConfig.endpoint = formData.get('browserless_endpoint') || browserlessConfig.endpoint;
            browserlessConfig.api_token = formData.get('browserless_api_token') || '';
            browserlessConfig.timeout_seconds = Math.max(30, Number(formData.get('browserless_timeout_seconds') || 120));

            megaUploadConfig.enabled = formData.get('mega_upload_enabled') === 'on';
            megaUploadConfig.pool_name = formData.get('mega_pool_name') || 'Mega Pool';
            megaUploadConfig.target_strategy = formData.get('target_strategy') || 'round_robin';
            megaUploadConfig.max_upload_mb = Math.max(1, Number(formData.get('max_upload_mb') || 100));
            megaUploadConfig.allow_automated_account_creation = formData.get('allow_automated_account_creation') === 'on';

            await persistRuntimeSettings(env);

            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Settings saved.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Settings error: ' + e.message), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    // Browserless health check
    if (path === '/dashboard/browserless-test' && method === 'POST') {
        try {
            if (!browserlessConfig.enabled) {
                throw new Error('Browserless is disabled.');
            }
            if (!browserlessConfig.api_token) {
                throw new Error('Browserless API token is missing.');
            }

            const code = `export default async function ({ page }) {
                await page.goto('https://mega.nz/', { waitUntil: 'domcontentloaded' });
                return { data: { title: await page.title() }, type: 'application/json' };
            };`;
            const result = await callBrowserlessFunction(code);
            return new Response(JSON.stringify({ success: true, title: result?.data?.title || 'MEGA' }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // Upload status endpoint
    if (path === '/dashboard/mega-upload-status' && method === 'GET') {
        await ensureMegaUploadDrives(megaDrives);
        const writableDrives = megaDrives.filter(drive => drive && !drive.isPublicFolder && drive.masterKey && drive.sid);
        const writable = writableDrives.length;
        const ready = Boolean(megaUploadConfig.enabled && writable > 0);
        const message = ready
            ? `${megaUploadConfig.pool_name || 'Mega Pool'} is ready. ${writable} writable MEGA root(s) available.`
            : 'Enable admin uploads and configure at least one logged-in MEGA account root first.';
        const accounts = await Promise.all((megaConfig.accounts || []).map(async (account, index) => {
            const drive = megaDrives[(megaConfig.roots?.length || 0) + index];
            try {
                const storage = await drive.getStorageInfo();
                return { index, email: account.email || `MEGA Account ${index + 1}`, ready: true, ...storage };
            } catch (e) {
                return { index, email: account.email || `MEGA Account ${index + 1}`, ready: false, error: e.message };
            }
        }));
        const poolStorage = accounts.reduce((total, account) => ({
            total: total.total + (account.total || 0), used: total.used + (account.used || 0), free: total.free + (account.free || 0)
        }), { total: 0, used: 0, free: 0 });
        return new Response(JSON.stringify({
            enabled: ready,
            message,
            pool_name: megaUploadConfig.pool_name || 'Mega Pool',
            target_strategy: megaUploadConfig.target_strategy,
            accounts,
            pool_storage: poolStorage,
            writable_roots: writable,
            automated_account_creation: megaUploadConfig.allow_automated_account_creation
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // ===================== AJAX: Folder Tree Browser =====================
    if (path === '/dashboard/mega-pool-browse' && method === 'GET') {
        try {
            await ensureMegaUploadDrives(megaDrives);
            const writable = megaDrives.filter(drive => drive && !drive.isPublicFolder && drive.masterKey && drive.sid);
            if (!writable.length) {
                return new Response(JSON.stringify({ success: false, error: 'No writable MEGA accounts available.' }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // Use first writable account's folder tree
            const drive = writable[0];
            if (!drive.initialized) await drive.init();
            const folders = await drive.listFolders('/');
            return new Response(JSON.stringify({
                success: true,
                account: drive.account?.email || 'unknown',
                folders
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // ===================== AJAX: Upload File =====================
    if (path === '/dashboard/mega-upload-ajax' && method === 'POST') {
        try {
            const formData = await request.formData();
            const file = formData.get('file');
            const uploadPath = formData.get('upload_path') || '/';
            const target = formData.get('target') || 'mega_pool';
            const accountIndex = formData.get('account_index');
            const maxBytes = Number(megaUploadConfig.max_upload_mb || 2000) * 1024 * 1024;

            if (file?.size && file.size > maxBytes) {
                return new Response(JSON.stringify({
                    success: false,
                    error: `File exceeds ${megaUploadConfig.max_upload_mb} MB limit.`
                }), { headers: { 'Content-Type': 'application/json' } });
            }

            await ensureMegaUploadDrives(megaDrives);

            if (target === 'mega_pool_mirror') {
                // Mirror mode: upload to ALL writable accounts in parallel
                const writable = megaDrives.filter(d => d && !d.isPublicFolder && d.masterKey && d.sid);
                if (!writable.length) throw new Error('No writable MEGA accounts available.');

                const results = await Promise.allSettled(
                    writable.map(async drive => {
                        try {
                            await drive.ensureFolder(uploadPath);
                        } catch { /* folder may already exist */ }
                        return drive.uploadFile(file, uploadPath);
                    })
                );

                const succeeded = results.filter(r => r.status === 'fulfilled').length;
                const failed = results.filter(r => r.status === 'rejected');
                const firstResult = results.find(r => r.status === 'fulfilled')?.value || {};

                return new Response(JSON.stringify({
                    success: succeeded > 0,
                    mirror: true,
                    accounts_total: writable.length,
                    accounts_succeeded: succeeded,
                    accounts_failed: failed.length,
                    errors: failed.map(r => r.reason?.message || 'Unknown error'),
                    result: firstResult
                }), { headers: { 'Content-Type': 'application/json' } });
            } else {
                // Standard pool upload (round-robin or first)
                const drive = await selectMegaUploadTarget(megaDrives, accountIndex);
                try {
                    await drive.ensureFolder(uploadPath);
                } catch { /* folder may already exist */ }
                const result = await drive.uploadFile(file, uploadPath);
                return new Response(JSON.stringify({
                    success: true,
                    mirror: false,
                    account: drive.account?.email || 'pool',
                    result
                }), { headers: { 'Content-Type': 'application/json' } });
            }
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // ===================== AJAX: Create Folder =====================
    if (path === '/dashboard/mega-create-folder-ajax' && method === 'POST') {
        try {
            const formData = await request.formData();
            const parentPath = formData.get('parent_path') || '/';
            const folderName = formData.get('folder_name') || '';
            const mirror = formData.get('mirror') === 'true';
            const accountIndex = formData.get('account_index');

            if (!folderName.trim()) throw new Error('Folder name is required.');

            await ensureMegaUploadDrives(megaDrives);

            if (mirror) {
                // Mirror mode: create on ALL writable accounts
                const writable = megaDrives.filter(d => d && !d.isPublicFolder && d.masterKey && d.sid);
                if (!writable.length) throw new Error('No writable MEGA accounts available.');

                const results = await Promise.allSettled(
                    writable.map(async drive => {
                        try {
                            await drive.ensureFolder(parentPath);
                        } catch { /* parent may exist */ }
                        return drive.createFolder(parentPath, folderName.trim());
                    })
                );

                const succeeded = results.filter(r => r.status === 'fulfilled').length;
                const failed = results.filter(r => r.status === 'rejected');

                return new Response(JSON.stringify({
                    success: succeeded > 0,
                    mirror: true,
                    folder_name: folderName.trim(),
                    accounts_succeeded: succeeded,
                    accounts_failed: failed.length,
                    errors: failed.map(r => r.reason?.message || 'Unknown error')
                }), { headers: { 'Content-Type': 'application/json' } });
            } else {
                // Standard: create on one account
                const drive = await selectMegaUploadTarget(megaDrives, accountIndex);
                try {
                    await drive.ensureFolder(parentPath);
                } catch { /* parent may exist */ }
                const result = await drive.createFolder(parentPath, folderName.trim());
                return new Response(JSON.stringify({
                    success: true,
                    mirror: false,
                    account: drive.account?.email || 'pool',
                    result
                }), { headers: { 'Content-Type': 'application/json' } });
            }
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }


    if (path === '/dashboard/mega-account-add' && method === 'POST') {
        try {
            const formData = await request.formData();
            const email = String(formData.get('email') || '').trim().toLowerCase();
            const password = String(formData.get('password') || '');
            if (!email || !password) throw new Error('Email and password are required.');

            megaConfig.accounts = megaConfig.accounts || [];
            if (megaConfig.accounts.some(acc => String(acc.email || '').toLowerCase() === email)) {
                throw new Error('That MEGA account is already in the pool.');
            }
            megaConfig.accounts.push({ email, password });
            await persistRuntimeSettings(env);

            const { MegaDrive } = await import('./megaDrive.js');
            const accountIndex = megaConfig.accounts.length - 1;
            const order = (megaConfig.roots?.length || 0) + accountIndex;
            const newDrive = new MegaDrive(megaConfig, order, {
                id: `account-${megaConfig.accounts.length - 1}`,
                name: email,
                public: true
            }, { email, password });
            await newDrive.init();
            megaDrives[order] = newDrive;

            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'MEGA account added to the upload pool.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'MEGA account add failed: ' + e.message), {
                status: 400,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    if (path === '/dashboard/mega-account-remove' && method === 'POST') {
        try {
            const formData = await request.formData();
            const index = Number(formData.get('index'));
            if (!Number.isInteger(index) || index < 0 || index >= (megaConfig.accounts || []).length) {
                throw new Error('Invalid account index.');
            }
            const [removed] = megaConfig.accounts.splice(index, 1);
            const driveIndex = megaDrives.findIndex(drive =>
                String(drive?.account?.email || '').toLowerCase() === String(removed?.email || '').toLowerCase()
            );
            if (driveIndex >= 0) megaDrives.splice(driveIndex, 1);
            await persistRuntimeSettings(env);
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'MEGA account removed from the upload pool.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'MEGA account remove failed: ' + e.message), {
                status: 400,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    if (path === '/dashboard/path-password-add' && method === 'POST') {
        try {
            const formData = await request.formData();
            const driveType = formData.get('drive_type') === 'mega' ? 'mega' : 'google';
            const driveIndex = Math.max(0, Number(formData.get('drive_index') || 0));
            const protectedPath = normalizeProtectedPath(formData.get('path') || '/');
            const password = String(formData.get('password') || '');
            const label = String(formData.get('label') || '').trim();
            if (!password) throw new Error('Password is required.');

            pathPasswordConfig.enabled = true;
            pathPasswordConfig.rules = pathPasswordConfig.rules || [];
            pathPasswordConfig.rules.push({
                drive_type: driveType,
                drive_index: driveIndex,
                path: protectedPath,
                password,
                label
            });
            await persistRuntimeSettings(env);
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Path password rule added.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Path password add failed: ' + e.message), {
                status: 400,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    if (path === '/dashboard/path-password-remove' && method === 'POST') {
        try {
            const formData = await request.formData();
            const index = Number(formData.get('index'));
            pathPasswordConfig.rules = pathPasswordConfig.rules || [];
            if (!Number.isInteger(index) || index < 0 || index >= pathPasswordConfig.rules.length) {
                throw new Error('Invalid password rule index.');
            }
            pathPasswordConfig.rules.splice(index, 1);
            await persistRuntimeSettings(env);
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Path password rule removed.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Path password remove failed: ' + e.message), {
                status: 400,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    // MEGA folder creation through direct MEGA API calls.
    if (path === '/dashboard/mega-create-folder' && method === 'POST') {
        const formData = await request.formData();
        const folderName = formData.get('folder_name');
        const parentPath = formData.get('parent_path') || '/';
        try {
            const drive = await selectMegaUploadDrive(megaDrives);
            const result = await drive.createFolder(parentPath, folderName);
            return new Response(getDashboardHTML(permissionsStore,
                `Folder created: ${result.path || `${parentPath}/${folderName}`}`), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            return new Response(getDashboardHTML(permissionsStore,
                `Folder create failed: ${e.message}`), {
                status: 502,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    // MEGA upload through direct MEGA API calls.
    if (path === '/dashboard/mega-upload' && method === 'POST') {
        const formData = await request.formData();
        const file = formData.get('file');
        const uploadPath = formData.get('upload_path') || '/';
        const maxBytes = Number(megaUploadConfig.max_upload_mb || 100) * 1024 * 1024;

        if (file?.size && file.size > maxBytes) {
            return new Response(getDashboardHTML(permissionsStore,
                `Upload rejected. File exceeds ${megaUploadConfig.max_upload_mb} MB.`), {
                status: 413,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }

        try {
            const drive = await selectMegaUploadDrive(megaDrives);
            const result = await drive.uploadFile(file, uploadPath);
            return new Response(getDashboardHTML(permissionsStore,
                `Upload completed: ${result.path || file?.name || 'file'}`), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            return new Response(getDashboardHTML(permissionsStore,
                `Upload failed: ${e.message}`), {
                status: 502,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    // Automated MEGA account creation via Browserless
    if (path === '/dashboard/mega-create-automated-account' && method === 'POST') {
        try {
            if (!browserlessConfig.enabled || !browserlessConfig.api_token) {
                throw new Error('Browserless must be enabled with a valid API token in settings.');
            }
            if (!megaUploadConfig.allow_automated_account_creation) {
                throw new Error('Automated account creation is disabled in settings.');
            }

            // 1. Create temp mail
            const mailAccount = await createMailTmAccount();
            const { email, token } = mailAccount;
            const megaPassword = randomPassword(20);

            // 2. Register on MEGA via Browserless
            const registerCode = `export default async function ({ page }) {
                const email = ${JSON.stringify(email)};
                const password = ${JSON.stringify(megaPassword)};
                await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                await page.goto('https://mega.nz/register', { waitUntil: 'domcontentloaded', timeout: 60000 });
                await new Promise(r => setTimeout(r, 3000));
                await page.waitForSelector('input', { visible: true, timeout: 30000 });
                const isUsable = async (el) => el.evaluate(node => {
                    if (!(node instanceof HTMLElement)) return false;
                    const style = window.getComputedStyle(node);
                    const rect = node.getBoundingClientRect();
                    return !node.disabled && style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                });
                const typeFirst = async (selectors, value) => {
                    for (const selector of selectors) {
                        const elements = await page.$$(selector);
                        for (const el of elements) {
                            if (!(await isUsable(el))) continue;
                            await el.evaluate((node, newValue) => {
                                node.focus();
                                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                                if (setter) {
                                    setter.call(node, newValue);
                                } else {
                                    node.value = newValue;
                                }
                                node.dispatchEvent(new Event('input', { bubbles: true }));
                                node.dispatchEvent(new Event('change', { bubbles: true }));
                            }, value);
                            return true;
                        }
                    }
                    return false;
                };
                await typeFirst(['#register-firstname', 'input.first-name', 'input[name="first-name"]', 'input[placeholder*="First" i]'], 'MEGA');
                await typeFirst(['#register-lastname', 'input.last-name', 'input[name="last-name"]', 'input[placeholder*="Last" i]'], 'User');
                const emailOk = await typeFirst(['#register-email', 'input.email-input', 'input[type="email"]', 'input[name="email"]'], email);
                const passOk = await typeFirst(['#register-password', 'input.password-input', 'input[type="password"]', 'input[name="password"]'], password);
                if (!emailOk || !passOk) {
                    const inputs = await page.$$eval('input', els => els.map(el => ({
                        id: el.id,
                        name: el.name,
                        type: el.type,
                        visible: el.offsetParent !== null,
                        disabled: el.disabled
                    })));
                    throw new Error('MEGA registration form fields were not found: ' + JSON.stringify(inputs).slice(0, 500));
                }
                
                // Toggle terms checkboxes
                const checkboxes = await page.$$('input[type="checkbox"]');
                for (const cb of checkboxes) {
                    const checked = await cb.evaluate(el => {
                        if (el instanceof HTMLInputElement && !el.checked && !el.disabled && el.offsetParent !== null) {
                            el.click();
                            return true;
                        }
                        return false;
                    });
                    if (checked) break;
                }
                
                const submit = await page.$('button.register-button, button[type="submit"], .register-button, button.fm-dialog-new-folder-button');
                if (submit) {
                    await submit.evaluate(el => el.click());
                } else {
                    await page.keyboard.press('Enter');
                }
                await new Promise(r => setTimeout(r, 8000));
                const bodyText = await page.evaluate(() => document.body.innerText);
                return { data: { success: true, body: bodyText }, type: 'application/json' };
            };`;

            await callBrowserlessFunction(registerCode);
            
            // 3. Poll mail.tm for the verification email
            let verifyUrl = null;
            const pollStart = Date.now();
            const timeoutMs = 120000; // 2 mins
            while (Date.now() - pollStart < timeoutMs) {
                const msgsResp = await fetch('https://api.mail.tm/messages', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (msgsResp.ok) {
                    const msgsData = await msgsResp.json();
                    const msgs = msgsData['hydra:member'] || msgsData;
                    let foundMsg = null;
                    for (const m of msgs) {
                        const subj = (m.subject || '').toLowerCase();
                        if (subj.includes('mega') || subj.includes('confirm')) {
                            foundMsg = m;
                            break;
                        }
                    }
                    if (foundMsg) {
                        const fullMsgResp = await fetch(`https://api.mail.tm/messages/${foundMsg.id}`, {
                            headers: { 'Authorization': `Bearer ${token}` }
                        });
                        if (fullMsgResp.ok) {
                            const fullMsg = await fullMsgResp.json();
                            const body = fullMsg.html?.[0] || fullMsg.text || fullMsg.intro || JSON.stringify(fullMsg);
                            
                            // Extract verification link
                            const patterns = [
                                /https?:\/\/mega\.nz\/#confirm_email,[^\s"'<>\\)]+/i,
                                /https?:\/\/mega\.nz\/#confirmQ[^\s"'<>\\)]+/i,
                                /https?:\/\/mega\.nz\/signup\/confirm[^\s"'<>\\)]+/i,
                                /https?:\/\/mega\.nz\/confirm[^\s"'<>\\)]+/i
                            ];
                            for (const pat of patterns) {
                                const match = body.match(pat);
                                if (match) {
                                    verifyUrl = match[0].replace(/["'()]/g, '');
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
                await new Promise(r => setTimeout(r, 4000));
            }

            if (!verifyUrl) {
                throw new Error('Failed to receive or parse the MEGA verification email in time.');
            }

            // 4. Verify account on MEGA via Browserless
            const verifyCode = `export default async function ({ page }) {
                const verifyUrl = ${JSON.stringify(verifyUrl)};
                const password = ${JSON.stringify(megaPassword)};
                await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                await page.goto(verifyUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
                await new Promise(r => setTimeout(r, 5000));
                
                const hasPassword = await page.evaluate(() => {
                    const text = document.body.innerText.toLowerCase();
                    return text.includes('confirm your account') && text.includes('password');
                });
                if (hasPassword) {
                    await page.waitForSelector('input[type="password"]', { visible: true, timeout: 15000 });
                    const passInputs = await page.$$('input[type="password"]');
                    let passInput = null;
                    for (const input of passInputs) {
                        const visible = await input.evaluate(el => el.offsetParent !== null && !el.disabled);
                        if (visible) {
                            passInput = input;
                            break;
                        }
                    }
                    if (!passInput) {
                        throw new Error('MEGA confirmation password field was not visible.');
                    }
                    if (passInput) {
                        await passInput.evaluate((node, newValue) => {
                            node.focus();
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                            if (setter) {
                                setter.call(node, newValue);
                            } else {
                                node.value = newValue;
                            }
                            node.dispatchEvent(new Event('input', { bubbles: true }));
                            node.dispatchEvent(new Event('change', { bubbles: true }));
                        }, password);
                    }
                    await new Promise(r => setTimeout(r, 1000));
                    
                    const confirmBtn = await page.evaluateHandle(() => {
                        const candidates = Array.from(document.querySelectorAll('button, .register-button, [role="button"]'));
                        return candidates.find(el => {
                            const text = (el.innerText || el.textContent || '').trim().toLowerCase();
                            const rect = el.getBoundingClientRect();
                            const style = window.getComputedStyle(el);
                            return text.includes('confirm') && style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
                        }) || null;
                    });
                    const confirmElement = confirmBtn?.asElement?.();
                    if (confirmElement) {
                        await confirmElement.evaluate(el => el.click());
                    } else {
                        await page.keyboard.press('Enter');
                    }
                    await new Promise(r => setTimeout(r, 10000));
                }
                
                const bodyText = await page.evaluate(() => document.body.innerText);
                const success = /you're in control|generating your unique|recovery key|cloud drive|welcome/i.test(bodyText);
                if (!success) {
                    return { data: { success: false, body: bodyText.slice(0, 1000) }, type: 'application/json' };
                }
                return { data: { success: true, body: bodyText }, type: 'application/json' };
            };`;

            const verifyResult = await callBrowserlessFunction(verifyCode);
            if (verifyResult?.data?.success === false) {
                throw new Error('MEGA verification status unclear: ' + (verifyResult.data.body || '').slice(0, 300));
            }

            // 5. Add to accounts and save settings
            megaConfig.accounts = megaConfig.accounts || [];
            megaConfig.accounts.push({ email, password: megaPassword });

            await persistRuntimeSettings(env);

            // 6. Initialize the new drive immediately
            const { MegaDrive } = await import('./megaDrive.js');
            const accountIndex = megaConfig.accounts.length - 1;
            const order = (megaConfig.roots?.length || 0) + accountIndex;
            const newDrive = new MegaDrive(megaConfig, order, {
                id: `account-${accountIndex}`,
                name: email,
                public: true
            }, { email, password: megaPassword });
            await newDrive.init();
            megaDrives[order] = newDrive;

            return new Response(JSON.stringify({ success: true, email, password: megaPassword }), {
                headers: { 'Content-Type': 'application/json' }
            });

        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
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
            await persistRuntimeSettings(env);
        }

        return new Response('', {
            status: 302,
            headers: { 'Location': '/dashboard' }
        });
    }

    // Add folder/root
    if (path === '/dashboard/add-folder' && method === 'POST') {
        try {
            const formData = await request.formData();
            const type = formData.get('type');
            const name = String(formData.get('name') || '').trim();
            const access = formData.get('access');
            if (!name) throw new Error('Folder name is required.');

            if (type === 'mega') {
                const link = String(formData.get('mega_link') || '').trim();
                if (!link) throw new Error('MEGA folder link is required.');
                megaConfig.roots = megaConfig.roots || [];
                megaConfig.roots.push({
                    link,
                    name,
                    public: access !== 'private',
                    ...(access === 'private' ? { auth: {} } : {})
                });
            } else {
                const id = String(formData.get('id') || '').trim();
                if (!id) throw new Error('Google Drive folder ID is required.');
                authConfig.roots.push({
                    id,
                    name,
                    protect_file_link: false,
                    ...(access === 'private' ? { auth: {} } : {})
                });
            }

            permissionsStore = {};
            initPermissions();
            await persistRuntimeSettings(env);
            return new Response(getDashboardHTML(permissionsStore, 'Folder added. Redeploy or restart the worker if the new drive is not listed immediately.'), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            initPermissions();
            return new Response(getDashboardHTML(permissionsStore, 'Add folder failed: ' + e.message), {
                status: 400,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
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
            await persistRuntimeSettings(env);
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
        await persistRuntimeSettings(env);
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
        await persistRuntimeSettings(env);
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
                    'Invalid configuration: ' + validation.errors.join(', ')), {
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
            
            const message = `Imported ${imported.googleDriveRoots.length} Google Drive(s) and ${imported.megaRoots.length} Mega.nz folder(s)` +
                (imported.errors.length > 0 ? '. Warnings: ' + imported.errors.join(', ') : '');
            
            return new Response(getDashboardHTML(permissionsStore, message), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        } catch (e) {
            return new Response(getDashboardHTML(permissionsStore, 'Import error: ' + e.message), {
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
                if (perm.public) {
                    delete root.auth;
                } else {
                    root.auth = perm.auth || {};
                }
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
    selectMegaUploadDrive,
    ensureMegaUploadDrives,
    isAdminBasicAuthenticated,
    adminAuthResponse,
    permissionsStore
};
