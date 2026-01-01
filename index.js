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
import { handleDashboard } from './dashboard.js';

// Global drive instances
var gds = [];
var megaDrives = [];

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

    // Initialize Google Drive instances
    if (gds.length === 0) {
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

    // Initialize Mega.nz drives
    if (megaDrives.length === 0 && megaConfig.enabled) {
        megaDrives = await initMegaDrives();
    }

    let gd;
    let url = new URL(request.url);
    let path = url.pathname;
    let hostname = url.hostname;

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
        return handleDashboard(request, url);
    }

    // Mega.nz routes: /mega0:/, /mega1:/, etc.
    const mega_reg = /^\/mega(?<num>\d+):(?<rest>\/.*)?$/g;
    const megaMatch = mega_reg.exec(path);
    if (megaMatch && megaConfig.enabled) {
        const num = parseInt(megaMatch.groups.num);
        if (num >= 0 && num < megaDrives.length) {
            return handleMegaRequest(request, megaDrives[num], megaMatch.groups.rest || '/');
        }
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
        for (const r = gd.basicAuthResponse(request); r;) return r;
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
async function handleMegaRequest(request, megaDrive, path) {
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
        return new Response(html(megaDrive.order, {
            root_type: 2, // Mega type
            is_mega: true
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
        const range = request.headers.get('Range') || '';
        const inline = url.searchParams.get('inline') === 'true';
        return megaDrive.down(file.id, range, inline);
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

        if (authConfig['enable_password_file_verify']) {
            let password = await gd.password(path);
            if (password && password.replace("\n", "") !== form.get('password')) {
                let html = `Y29kZWlzcHJvdGVjdGVk=0Xfi4icvJnclBCZy92dzNXYwJCI6ISZnF2czVWbiwSMwQDI6ISZk92YisHI6IicvJnclJyeYmFzZTY0aXNleGNsdWRlZA==`;
                return new Response(html, option);
            }
        }

        let list_result = await deferred_list_result;
        return new Response(rewrite(gdiencode(JSON.stringify(list_result), option)));
    } else {
        let file = await gd.file(path);
        let range = request.headers.get('Range');
        return new Response(rewrite(gdiencode(JSON.stringify(file))));
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
    return new Response(rewrite(gdiencode(JSON.stringify(search_result), option)));
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
