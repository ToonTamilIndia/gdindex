import { adConfig, browserlessConfig, megaUploadConfig, uiConfig, megaConfig, pathPasswordConfig, authConfig } from './config.js';

const SETTINGS_KEY = 'settings:runtime';

function getLinkStore(env) {
    return env?.LINK_STORE || globalThis.LINK_STORE || null;
}

function randomId(length = 24) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function getAction(url) {
    return url.searchParams.get('a') === 'view' ? 'view' : 'download';
}

function getExpirySeconds(action) {
    return action === 'view' ? adConfig.view_expiry_seconds : adConfig.download_expiry_seconds;
}

function publicUrlWithId(url, id) {
    const next = new URL(url.toString());
    next.searchParams.set('id', id);
    return next.toString();
}

function recordKey(id) {
    return `adlink:${id}`;
}

function isSameTarget(record, url) {
    return record.pathname === url.pathname && record.action === getAction(url);
}

function hostMatches(hostname, allowedHost) {
    return hostname === allowedHost || hostname.endsWith(`.${allowedHost}`);
}

function hasAllowedReturnReferer(request) {
    if (!adConfig.require_return_referer) return true;

    const referer = request.headers.get('Referer') || '';
    if (!referer) return false;

    try {
        const refererUrl = new URL(referer);
        const allowed = adConfig.allowed_return_referers || [];
        return allowed.some(host => hostMatches(refererUrl.hostname.toLowerCase(), String(host).toLowerCase()));
    } catch {
        return false;
    }
}

async function shortenUrl(longUrl) {
    if (!adConfig.api_token) return longUrl;

    const apiUrl = new URL(adConfig.api_endpoint || 'https://api.gplinks.com/api');
    apiUrl.searchParams.set('api', adConfig.api_token);
    apiUrl.searchParams.set('url', longUrl);
    apiUrl.searchParams.set('format', 'text');

    const res = await fetch(apiUrl.toString());
    if (!res.ok) return longUrl;

    const text = (await res.text()).trim();
    return text || longUrl;
}

async function createGateRecord(request, env) {
    const store = getLinkStore(env);
    if (!store) {
        return new Response('LINK_STORE KV binding is required when ad shortener is enabled.', { status: 500 });
    }

    const url = new URL(request.url);
    const action = getAction(url);
    const id = randomId();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = getExpirySeconds(action);
    const returnUrl = publicUrlWithId(url, id);

    const record = {
        id,
        action,
        pathname: url.pathname,
        createdAt: now,
        minWaitSeconds: Number(adConfig.min_wait_seconds || 10),
        expiresAt: now + expiresIn
    };

    await store.put(recordKey(id), JSON.stringify(record), { expirationTtl: expiresIn + 300 });

    const redirectUrl = await shortenUrl(returnUrl);
    return Response.redirect(redirectUrl, 302);
}

async function validateGateRecord(request, env) {
    const store = getLinkStore(env);
    const url = new URL(request.url);
    const id = url.searchParams.get('id');

    if (!id) return createGateRecord(request, env);
    if (!store) {
        return new Response('LINK_STORE KV binding is required when ad shortener is enabled.', { status: 500 });
    }

    const raw = await store.get(recordKey(id));
    if (!raw) return createGateRecord(request, env);

    let record;
    try {
        record = JSON.parse(raw);
    } catch {
        return createGateRecord(request, env);
    }

    const now = Math.floor(Date.now() / 1000);
    if (!isSameTarget(record, url) || now > record.expiresAt) {
        return createGateRecord(request, env);
    }

    if (!hasAllowedReturnReferer(request)) {
        return createGateRecord(request, env);
    }

    if (now - record.createdAt < record.minWaitSeconds) {
        return createGateRecord(request, env);
    }

    return null;
}

async function maybeHandleAdGate(request, env) {
    if (!adConfig.enabled) return null;
    if (request.method !== 'GET' && request.method !== 'HEAD') return null;
    return validateGateRecord(request, env);
}

async function loadRuntimeSettings(env) {
    const store = getLinkStore(env);
    if (!store) return;

    const raw = await store.get(SETTINGS_KEY);
    if (!raw) return;

    try {
        const settings = JSON.parse(raw);
        if (settings.ui) Object.assign(uiConfig, settings.ui);
        if (settings.ad) Object.assign(adConfig, settings.ad);
        if (settings.browserless) Object.assign(browserlessConfig, settings.browserless);
        if (settings.megaUpload) Object.assign(megaUploadConfig, settings.megaUpload);
        if (settings.pathPasswords) Object.assign(pathPasswordConfig, settings.pathPasswords);
        if (Array.isArray(settings.googleRoots)) authConfig.roots = settings.googleRoots;
        if (Array.isArray(settings.megaRoots)) megaConfig.roots = settings.megaRoots;
        
        if (settings.megaAccounts && Array.isArray(settings.megaAccounts)) {
            megaConfig.accounts = settings.megaAccounts;
        }
    } catch (e) {
        console.error('Runtime settings parse error:', e);
    }
}

function normalizeTheme(theme) {
    return theme === 'dark' ? 'darkly' : theme;
}

async function saveRuntimeSettings(env, settings) {
    const store = getLinkStore(env);
    if (!store) throw new Error('LINK_STORE KV binding is not configured.');
    await store.put(SETTINGS_KEY, JSON.stringify(settings));
}

export {
    maybeHandleAdGate,
    loadRuntimeSettings,
    saveRuntimeSettings,
    normalizeTheme
};
