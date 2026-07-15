/*  ░██████╗░██████╗░██╗░░░░░░░░██╗░██████╗░░░░█████╗░██████╗░░██████╗░
    ██╔════╝░██╔══██╗██║░░░░░░░░██║██╔════╝░░░██╔══██╗██╔══██╗██╔════╝░
    ██║░░██╗░██║░░██║██║░░░░░░░░██║╚█████╗░░░░██║░░██║██████╔╝██║░░██╗░
    ██║░░╚██╗██║░░██║██║░░░██╗░░██║░╚═══██╗░░░██║░░██║██╔══██╗██║░░╚██╗
    ╚██████╔╝██████╔╝██║██╗╚█████╔╝██████╔╝██╗╚█████╔╝██║░░██║╚██████╔╝
    ░╚═════╝░╚═════╝░╚═╝╚═╝░╚════╝░╚═════╝░╚═╝░╚════╝░╚═╝░░╚═╝░╚═════╝░
                             v 2.3.0 - Modular
                        Mega.nz Support & Dashboard
    
    Features:
    - Modular file structure
    - Mega.nz cloud storage support  
    - Permission management dashboard (/dashboard)
    - Auth0 integration
    - Multiple drive support
*/

// Import configurations
import { 
    authConfig, 
    uiConfig, 
    megaConfig, 
    pathPasswordConfig,
    blocked_region, 
    blocked_asn 
} from './config.js';

// Import utilities
import { gdiencode, rewrite } from './utils.js';

// Import templates
import { 
    html, 
    getHomepage, 
    not_found, 
    asn_blocked, 
    directlink 
} from './templates.js';

// Import handlers
import { GoogleDrive } from './googleDrive.js';
import { MegaDrive, initMegaDrives } from './megaDrive.js';
import { loginHandleRequest } from './auth.js';
import { handleDashboard, selectMegaUploadDrive, isAdminBasicAuthenticated, adminAuthResponse } from './dashboard.js';
import { loadRuntimeSettings, maybeHandleAdGate } from './adGate.js';

// Global drive instances
var gds = [];
var megaDrives = [];

async function ensureGoogleDrives() {
    if (gds.length > 0) return;
    for (let i = 0; i < authConfig.roots.length; i++) {
        const gd = new GoogleDrive(authConfig, i);
        await gd.init();
        gds.push(gd);
    }
    let tasks = [];
    gds.forEach(gd => {
        tasks.push(gd.initRootType());
    });
    for (let task of tasks) {
        await task;
    }
}

function getMegaDrive(order) {
    if (!megaConfig.enabled || order < 0) return null;
    if (megaDrives[order]) return megaDrives[order];

    const roots = megaConfig.roots || [];
    const accounts = megaConfig.accounts || [];
    let drive = null;

    if (order < roots.length) {
        drive = new MegaDrive(megaConfig, order, roots[order], accounts[order] || null);
    } else {
        const accountIndex = order - roots.length;
        const account = accounts[accountIndex];
        if (account) {
            drive = new MegaDrive(megaConfig, order, {
                id: `account-${accountIndex}`,
                name: account.email || `MEGA Account ${accountIndex + 1}`,
                public: true
            }, account);
        }
    }

    if (drive) megaDrives[order] = drive;
    return drive;
}

// ES Module format - default export for Cloudflare Workers
export default {
    async fetch(request, env, ctx) {
        try {
            return await handleRequest(request, { request, env, ctx });
        } catch (err) {
            return new Response(
                "GDI Error Handler Version : 2.3.0\n" +
                "Report this Error to Email : admin@hashhackers.com\n" +
                "Include : Full details, including screenshot and links\n\n\n" + 
                err.stack, 
                { status: 500 }
            );
        }
    }
};

// Main request handler
async function handleRequest(request, event) {
    await loadRuntimeSettings(event.env);

    // Handle Auth0 login if enabled
    var loginCheck = await loginHandleRequest(event);
    if (authConfig['enable_auth0_com'] && loginCheck != null) {
        return loginCheck;
    }

    const region = request.headers.get('cf-ipcountry')?.toUpperCase() || '';
    var asn_servers = '';
    try { 
        asn_servers = request.cf.asn; 
    } catch { 
        asn_servers = 0; 
    }
    const referer = request.headers.get("Referer");
    let url = new URL(request.url);
    let path = url.pathname;
    let hostname = url.hostname;
    let gd;

    function redirectToIndexPage() {
        return new Response('', {
            status: 307,
            headers: {
                'Location': `${url.origin}/0:/`
            }
        });
    }

    // Check blocked regions
    if (blocked_region.includes(region)) {
        return new Response(asn_blocked, {
            status: 403,
            headers: {
                "content-type": "text/html;charset=UTF-8",
            },
        });
    }

    // Check blocked ASN
    if (blocked_asn.includes(asn_servers)) {
        return new Response(asn_blocked, {
            headers: {
                'content-type': 'text/html;charset=UTF-8'
            },
            status: 401
        });
    }

    // Home page
    if (path == '/') {
        return new Response(getHomepage(), {
            status: 200,
            headers: {
                "content-type": "text/html;charset=UTF-8",
            },
        });
    }

    // Dashboard routes
    if (path.startsWith('/dashboard')) {
        return handleDashboard(request, url, event.env, megaDrives);
    }

    // Mega.nz routes: /mega0:/, /mega1:/, etc.
    const mega_reg = /^\/mega(?<num>\d+):(?<rest>\/.*)?$/g;
    const megaMatch = mega_reg.exec(path);
    if (megaMatch && megaConfig.enabled) {
        const num = parseInt(megaMatch.groups.num);
        const megaDrive = getMegaDrive(num);
        if (megaDrive) {
            return handleMegaRequest(request, megaDrive, megaMatch.groups.rest || '/', event.env);
        }
    }

    await ensureGoogleDrives();

    if (path === '/api/upload' || path === '/api/create-folder') {
        return handleAdminUploadApi(request, url, gds, megaDrives, event.env);
    }

    // Direct link protection
    if (authConfig['direct_link_protection']) {
        if (referer == null) {
            return new Response(directlink, {
                headers: {
                    'content-type': 'text/html;charset=UTF-8'
                },
                status: 401
            });
        } else if (!referer.includes(hostname)) {
            return new Response(directlink, {
                headers: {
                    'content-type': 'text/html;charset=UTF-8'
                },
                status: 401
            });
        }
    }

    // Google Drive command routes: /0:search, /1:id2path, etc.
    const command_reg = /^\/(?<num>\d+):(?<command>[a-zA-Z0-9]+)(\/.*)?$/g;
    const match = command_reg.exec(path);
    if (match) {
        const num = match.groups.num;
        const order = Number(num);
        if (order >= 0 && order < gds.length) {
            gd = gds[order];
        } else {
            return redirectToIndexPage();
        }
        const r = gd.basicAuthResponse(request);
        if (r) return r;
        const command = match.groups.command;
        
        if (command === 'search') {
            if (request.method === 'POST') {
                return handleSearch(request, gd);
            } else {
                const params = url.searchParams;
                return new Response(html(gd.order, {
                    q: params.get("q")?.replace(/'/g, "").replace(/"/g, "") || '',
                    is_search_page: true,
                    root_type: gd.root_type
                }), {
                    status: 200,
                    headers: {
                        'Content-Type': 'text/html; charset=utf-8'
                    }
                });
            }
        } else if (command === 'id2path' && request.method === 'POST') {
            return handleId2Path(request, gd);
        }
    }

    // Standard Google Drive path routes: /0:/, /1:/path/to/file, etc.
    const common_reg = /^\/\d+:\/.*$/g;
    try {
        if (!path.match(common_reg)) {
            return redirectToIndexPage();
        }
        let split = path.split("/");
        let order = Number(split[1].slice(0, -1));
        if (order >= 0 && order < gds.length) {
            gd = gds[order];
        } else {
            return redirectToIndexPage();
        }
    } catch (e) {
        return redirectToIndexPage();
    }

    const basic_auth_res = gd.basicAuthResponse(request);

    path = path.replace(gd.url_path_prefix, '') || '/';
    
    // Handle POST requests (API calls)
    if (request.method == 'POST') {
        return basic_auth_res || apiRequest(request, gd);
    }

    let action = url.searchParams.get('a');

    // Directory listing or action
    if (path.substr(-1) == '/' || action != null) {
        if (action === 'view' && path.substr(-1) !== '/') {
            const adGateResponse = await maybeHandleAdGate(request, event.env);
            if (adGateResponse) return adGateResponse;
        }
        return basic_auth_res || new Response(html(gd.order, {
            root_type: gd.root_type
        }), {
            status: 200,
            headers: {
                'Content-Type': 'text/html; charset=utf-8'
            }
        });
    } else {
        // File download
        try {
            if (path.split('/').pop().toLowerCase() == ".password") {
                return basic_auth_res || new Response("", {
                    status: 404
                });
            }
            let file = await gd.file(path);
            let range = request.headers.get('Range');
            const inline_down = 'true' === url.searchParams.get('inline');
            if (gd.root.protect_file_link && basic_auth_res) return basic_auth_res;
            if (!verifyPathPassword('google', gd.order, path, requestPathPassword(request, url))) {
                return new Response('Password required', { status: 401 });
            }
            const adGateResponse = await maybeHandleAdGate(request, event.env);
            if (adGateResponse) return adGateResponse;
            return gd.down(file?.id, range, inline_down);
        } catch {
            return new Response(not_found, {
                status: 404,
                headers: {
                    "content-type": "text/html;charset=UTF-8",
                },
            });
        }
    }
}

// Handle Mega.nz requests
async function handleMegaRequest(request, megaDrive, path, env) {
    // Decode URL-encoded path
    path = decodeURIComponent(path);
    
    const basic_auth_res = megaDrive.basicAuthResponse(request);
    if (basic_auth_res) return basic_auth_res;

    const url = new URL(request.url);
    let action = url.searchParams.get('a');
    
    // Handle POST requests - return file/folder info in encoded format
    if (request.method === 'POST') {
        if (path.endsWith('/')) {
            // Directory listing
            try {
                let form = await request.formData();
                if (!verifyPathPassword('mega', megaDrive.order, path, form.get('password') || '')) {
                    return protectedFolderResponse({ status: 200, headers: { 'Access-Control-Allow-Origin': '*' } });
                }
                let result = await megaDrive.list(path, form.get('page_token'), Number(form.get('page_index') || 0));
                return new Response(rewrite(gdiencode(JSON.stringify(result))), {
                    status: 200,
                    headers: { 'Access-Control-Allow-Origin': '*' }
                });
            } catch (e) {
                // Return empty result on error
                return new Response(rewrite(gdiencode(JSON.stringify({ data: { files: [] } }))), {
                    status: 200,
                    headers: { 'Access-Control-Allow-Origin': '*' }
                });
            }
        } else {
            // File info request (for ?a=view player)
            const file = await megaDrive.file(path);
            if (file) {
                // Return file info in the format frontend expects
                const fileInfo = {
                    id: file.id,
                    name: file.name,
                    mimeType: file.mimeType,
                    size: String(file.size),
                    modifiedTime: file.modifiedTime
                };
                return new Response(rewrite(gdiencode(JSON.stringify(fileInfo))), {
                    status: 200,
                    headers: { 'Access-Control-Allow-Origin': '*' }
                });
            }
            return new Response(rewrite(gdiencode(JSON.stringify({}))), {
                status: 200,
                headers: { 'Access-Control-Allow-Origin': '*' }
            });
        }
    }
    
    // GET request with ?a=view or other action - show the HTML page
    if (action != null) {
        if (action === 'view' && !path.endsWith('/')) {
            const adGateResponse = await maybeHandleAdGate(request, env);
            if (adGateResponse) return adGateResponse;
        }
        return new Response(html(megaDrive.order, {
            root_type: 2, // Mega type
            is_mega: true,
            is_file: !path.endsWith('/')
        }), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }
    
    // Directory listing (GET)
    if (path.endsWith('/')) {
        return new Response(html(megaDrive.order, {
            root_type: 2, // Mega type
            is_mega: true
        }), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }
    
    // File download (GET without action)
    const file = await megaDrive.file(path);
    if (file) {
        const forceDownload = url.searchParams.get('download') === '1';
        // Chrome begins some attachment downloads with a tiny probe range.
        // The decrypted Worker stream cannot retain a Content-Length through
        // Cloudflare for that partial response, causing Chrome to treat the
        // probe as the whole download. Always stream the complete attachment.
        const range = forceDownload ? '' : (request.headers.get('Range') || '');
        // A download link must win over the default media-inline behavior.
        // Relying on the HTML download attribute alone is unreliable cross-origin.
        const inline = url.searchParams.get('inline') === 'true' && url.searchParams.get('download') !== '1';

        // HLS mode - serve m3u8 for MPEG-TS files
        if (url.searchParams.get('hls') === '1') {
            const { isTS, bitrate, totalDuration } = await megaDrive.probeHLS(file.id);
            if (isTS) {
                const base = url.origin + url.pathname;
                const fileSize = file.size || 0;
                if (fileSize <= 0) {
                    return new Response('Cannot build HLS playlist without file size', {
                        status: 400,
                        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' }
                    });
                }

                const totalDur = totalDuration && totalDuration > 0 ? totalDuration : 0;

                const effectiveBitrate = bitrate > 0 ? bitrate : Math.max(1, (fileSize * 8) / (totalDur > 0 ? totalDur : 60));
                // MEGA has high per-request latency. Larger HLS segments reduce
                // the number of upstream range requests during playback.
                const targetSegDur = 30;
                const TS_PKT = 188;
                const bytesPerSeg = Math.max(TS_PKT, Math.floor((effectiveBitrate * targetSegDur) / 8));
                const numSegs = Math.max(1, Math.ceil(fileSize / bytesPerSeg));
                const SEG_DUR = Math.max(8, Math.min(30, Math.ceil((fileSize * 8) / (effectiveBitrate * Math.max(1, numSegs)))));
                let m3u8 = '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:' + SEG_DUR + '\n#EXT-X-MEDIA-SEQUENCE:0\n';
                let elapsed = 0;
                for (let i = 0; i < numSegs; i++) {
                    const rawStart = i * bytesPerSeg;
                    const s = Math.floor(rawStart / TS_PKT) * TS_PKT;
                    const rawEnd = (i < numSegs - 1) ? (i + 1) * bytesPerSeg - 1 : fileSize - 1;
                    const e = Math.min(Math.ceil((rawEnd + 1) / TS_PKT) * TS_PKT - 1, fileSize - 1);
                    const segUrl = base + '?ts=1&start=' + s + '&end=' + e;
                    const segBytes = e - s + 1;
                    let dur = Math.max(0.1, (segBytes * 8) / effectiveBitrate);
                    if (i === numSegs - 1 && totalDur > 0) {
                        dur = Math.max(0.1, totalDur - elapsed);
                    }
                    elapsed += dur;
                    m3u8 += '#EXTINF:' + dur.toFixed(3) + ',\n' + segUrl + '\n';
                }
                m3u8 += '#EXT-X-ENDLIST\n';

                return new Response(m3u8, {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/vnd.apple.mpegurl',
                        'Access-Control-Allow-Origin': '*',
                        'Cache-Control': 'no-cache'
                    }
                });
            }
            return new Response('Not an MPEG-TS file', {
                status: 400,
                headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' }
            });
        }

        const serveTs = url.searchParams.get('ts') === '1';
        const hlsStart = parseInt(url.searchParams.get('start'));
        const hlsEnd   = parseInt(url.searchParams.get('end'));
        const hasHlsRange = !isNaN(hlsStart) && !isNaN(hlsEnd);

        if (!verifyPathPassword('mega', megaDrive.order, path, requestPathPassword(request, url))) {
            return new Response('Password required', { status: 401 });
        }
        const adGateResponse = await maybeHandleAdGate(request, env);
        if (adGateResponse) return adGateResponse;
        return megaDrive.down(
            file.id, range, inline, 'GET', serveTs,
            hasHlsRange ? hlsStart : -1,
            hasHlsRange ? hlsEnd : -1,
            forceDownload
        );
    }

    return new Response(not_found, {
        status: 404,
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}

// API request handler for directory listing and file info
async function apiRequest(request, gd) {
    let url = new URL(request.url);
    let path = url.pathname;
    path = path.replace(gd.url_path_prefix, '') || '/';

    let option = {
        status: 200,
        headers: {
            'Access-Control-Allow-Origin': '*'
        }
    };

    if (path.substr(-1) == '/') {
        let form = await request.formData();
        let deferred_list_result = gd.list(path, form.get('page_token'), Number(form.get('page_index')));

        if (isPathPasswordProtected('google', gd.order, path)) {
            const password = form.get('password') || '';
            if (!verifyPathPassword('google', gd.order, path, password)) {
                return protectedFolderResponse(option);
            }
        } else if (authConfig['enable_password_file_verify']) {
            let password = await gd.password(path);
            if (password && password.replace("\n", "") !== form.get('password')) {
                return protectedFolderResponse(option);
            }
        }

        let list_result = await deferred_list_result;
        return new Response(rewrite(gdiencode(JSON.stringify(list_result))), option);
    } else {
        let file = await gd.file(path);
        return new Response(rewrite(gdiencode(JSON.stringify(file))), option);
    }
}

function protectedFolderResponse(option) {
    const body = `Y29kZWlzcHJvdGVjdGVk=0Xfi4icvJnclBCZy92dzNXYwJCI6ISZnF2czVWbiwSMwQDI6ISZk92YisHI6IicvJnclJyeYmFzZTY0aXNleGNsdWRlZA==`;
    return new Response(body, option);
}

function normalizePathForPassword(path = '/') {
    let clean = '/' + String(path || '/').replace(/^\/+/, '');
    clean = clean.replace(/\/{2,}/g, '/');
    return clean;
}

function matchingPathPasswordRule(driveType, driveIndex, path) {
    if (!pathPasswordConfig.enabled) return null;
    const cleanPath = normalizePathForPassword(path);
    const rules = pathPasswordConfig.rules || [];
    return rules.find(rule => {
        const rulePath = normalizePathForPassword(rule.path || '/');
        const sameDrive = String(rule.drive_type || 'google') === driveType && Number(rule.drive_index || 0) === Number(driveIndex);
        if (!sameDrive) return false;
        if (rulePath.endsWith('/')) {
            return cleanPath === rulePath || cleanPath.startsWith(rulePath);
        }
        return cleanPath === rulePath;
    }) || null;
}

function isPathPasswordProtected(driveType, driveIndex, path) {
    return Boolean(matchingPathPasswordRule(driveType, driveIndex, path));
}

function verifyPathPassword(driveType, driveIndex, path, password) {
    const rule = matchingPathPasswordRule(driveType, driveIndex, path);
    if (!rule) return true;
    return String(rule.password || '') === String(password || '');
}

function requestPathPassword(request, url) {
    return request.headers.get('x-path-password') || url.searchParams.get('password') || '';
}

async function handleAdminUploadApi(request, url, gds, megaDrives, env = {}) {
    if (!isAdminBasicAuthenticated(request, env)) return adminAuthResponse();
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ success: false, error: 'Use POST multipart/form-data.' }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const form = await request.formData();
        const target = String(form.get('target') || 'mega_pool');
        const driveIndex = Math.max(0, Number(form.get('drive_index') || 0));
        const uploadPath = form.get('path') || form.get('upload_path') || '/';
        let result;

        // Mirror mode: operate on ALL writable MEGA accounts in parallel
        if (target === 'mega_pool_mirror') {
            const writable = megaDrives.filter(d => d && !d.isPublicFolder && d.masterKey && d.sid);
            if (!writable.length) throw new Error('No writable MEGA accounts available for mirror.');

            if (url.pathname === '/api/create-folder') {
                const folderName = form.get('folder_name') || form.get('name');
                const results = await Promise.allSettled(
                    writable.map(async drive => {
                        try { await drive.ensureFolder(uploadPath); } catch {}
                        return drive.createFolder(uploadPath, folderName);
                    })
                );
                const succeeded = results.filter(r => r.status === 'fulfilled').length;
                result = { mirror: true, accounts_total: writable.length, accounts_succeeded: succeeded };
            } else {
                const file = form.get('file');
                const results = await Promise.allSettled(
                    writable.map(async drive => {
                        try { await drive.ensureFolder(uploadPath); } catch {}
                        return drive.uploadFile(file, uploadPath);
                    })
                );
                const succeeded = results.filter(r => r.status === 'fulfilled').length;
                const firstResult = results.find(r => r.status === 'fulfilled')?.value || {};
                result = { mirror: true, accounts_total: writable.length, accounts_succeeded: succeeded, ...firstResult };
            }
        } else if (url.pathname === '/api/create-folder') {
            const folderName = form.get('folder_name') || form.get('name');
            if (target === 'drive') {
                const drive = gds[driveIndex];
                if (!drive) throw new Error('Google Drive index not found.');
                result = await drive.createFolder(uploadPath, folderName);
            } else {
                const drive = target === 'mega' ? (megaDrives[driveIndex] || getMegaDrive(driveIndex)) : await selectMegaUploadDrive(megaDrives);
                if (!drive) throw new Error('MEGA drive index not found.');
                try { await drive.ensureFolder(uploadPath); } catch {}
                result = await drive.createFolder(uploadPath, folderName);
            }
        } else {
            const file = form.get('file');
            if (target === 'drive') {
                const drive = gds[driveIndex];
                if (!drive) throw new Error('Google Drive index not found.');
                result = await drive.uploadFile(file, uploadPath);
            } else {
                const drive = target === 'mega' ? (megaDrives[driveIndex] || getMegaDrive(driveIndex)) : await selectMegaUploadDrive(megaDrives);
                if (!drive) throw new Error('MEGA drive index not found.');
                try { await drive.ensureFolder(uploadPath); } catch {}
                result = await drive.uploadFile(file, uploadPath);
            }
        }

        return new Response(JSON.stringify({ success: true, target, result }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// Search handler
async function handleSearch(request, gd) {
    const option = {
        status: 200,
        headers: {
            'Access-Control-Allow-Origin': '*'
        }
    };
    let form = await request.formData();
    let search_result = await gd.search(
        form.get('q') || '', 
        form.get('page_token'), 
        Number(form.get('page_index'))
    );
    return new Response(rewrite(gdiencode(JSON.stringify(search_result))), option);
}

// ID to Path handler
async function handleId2Path(request, gd) {
    const option = {
        status: 200,
        headers: {
            'Access-Control-Allow-Origin': '*'
        }
    };
    let form = await request.formData();
    let path = await gd.findPathById(form.get('id'));
    return new Response(path || '', option);
}

// Export for potential external use
export { handleRequest, gds, megaDrives };
