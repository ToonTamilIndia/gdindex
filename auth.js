// Auth0 and Authentication Handler
import { auth0Config, authConfig } from './config.js';
import { getCookie } from './utils.js';

// Auth0 Constants
const AUTH0_DOMAIN = auth0Config.domain;
const AUTH0_CLIENT_ID = auth0Config.clientId;
const AUTH0_CLIENT_SECRET = auth0Config.clientSecret;
const AUTH0_CALLBACK_URL = auth0Config.callbackUrl;
const AUTH0_LOGOUT_URL = auth0Config.logoutUrl;
const SALT = 'keys565';
const cookieKey = 'AUTH0-AUTH';

// Generate state parameter for OAuth
const generateStateParam = async () => {
    if (authConfig['enable_auth0_com']) {
        const resp = await fetch('https://csprng.xyz/v1/api');
        const { Data: state } = await resp.json();
        await AUTH_STORE.put(`state-${state}`, true, { expirationTtl: 60 });
        return state;
    }
    return null;
};

// Exchange authorization code for tokens
const exchangeCode = async code => {
    const body = JSON.stringify({
        grant_type: 'authorization_code',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        code,
        redirect_uri: auth0Config.callbackUrl,
    });

    return persistAuth(
        await fetch(AUTH0_DOMAIN + '/oauth/token', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body,
        }),
    );
};

// Decode JWT token
const decodeJWT = function(token) {
    var output = token
        .split('.')[1]
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += '==';
            break;
        case 3:
            output += '=';
            break;
        default:
            throw 'Illegal base64url string!';
    }

    const result = atob(output);

    try {
        return decodeURIComponent(escape(result));
    } catch (err) {
        console.log(err);
        return result;
    }
};

// Validate JWT token
const validateToken = token => {
    try {
        const dateInSecs = d => Math.ceil(Number(d) / 1000);
        const date = new Date();

        let iss = token.iss;

        // ISS can include a trailing slash but should otherwise be identical
        iss = iss.endsWith('/') ? iss.slice(0, -1) : iss;

        if (iss !== AUTH0_DOMAIN) {
            throw new Error(
                `Token iss value (${iss}) doesn't match AUTH0_DOMAIN (${AUTH0_DOMAIN})`,
            );
        }

        if (token.aud !== AUTH0_CLIENT_ID) {
            throw new Error(
                `Token aud value (${token.aud}) doesn't match AUTH0_CLIENT_ID (${AUTH0_CLIENT_ID})`,
            );
        }

        if (token.exp < dateInSecs(date)) {
            throw new Error(`Token exp value is before current time`);
        }

        // Token should have been issued within the last day
        date.setDate(date.getDate() - 1);
        if (token.iat < dateInSecs(date)) {
            throw new Error(`Token was issued before one day ago and is now invalid`);
        }

        return true;
    } catch (err) {
        console.log(err.message);
        return false;
    }
};

// Persist authentication data
const persistAuth = async exchange => {
    const body = await exchange.json();

    if (body.error) {
        throw new Error(body.error);
    }

    const date = new Date();
    date.setDate(date.getDate() + 1);

    const decoded = JSON.parse(decodeJWT(body.id_token));
    const validToken = validateToken(decoded);
    if (!validToken) {
        return { status: 401 };
    }

    const text = new TextEncoder().encode(`${SALT}-${decoded.sub}`);
    const digest = await crypto.subtle.digest({ name: 'SHA-256' }, text);
    const digestArray = new Uint8Array(digest);
    const id = btoa(String.fromCharCode.apply(null, digestArray));

    await AUTH_STORE.put(id, JSON.stringify(body));

    const headers = {
        Location: '/',
        'Set-cookie': `${cookieKey}=${id}; Secure; HttpOnly; SameSite=Lax; Expires=${date.toUTCString()}`,
    };

    return { headers, status: 302 };
};

// Build redirect URL
const redirectUrl = state =>
    `${auth0Config.domain}/authorize?response_type=code&client_id=${
        auth0Config.clientId
    }&redirect_uri=${
        auth0Config.callbackUrl
    }&scope=openid%20profile%20email&state=${encodeURIComponent(state)}`;

// Handle OAuth redirect
const handleRedirect = async event => {
    const url = new URL(event.request.url);

    const state = url.searchParams.get('state');
    if (!state) {
        return null;
    }

    const storedState = await AUTH_STORE.get(`state-${state}`);
    if (!storedState) {
        return null;
    }

    const code = url.searchParams.get('code');
    if (code) {
        return exchangeCode(code);
    }

    return null;
};

// Verify existing session
const verify = async event => {
    const cookieHeader = event.request.headers.get('Cookie');

    if (cookieHeader && cookieHeader.includes(cookieKey)) {
        if (!getCookie(cookieHeader, cookieKey)) return {};
        const sub = getCookie(cookieHeader, cookieKey);

        const kvData = await AUTH_STORE.get(sub);
        if (!kvData) {
            return {};
        }

        let kvStored;
        try {
            kvStored = JSON.parse(kvData);
        } catch (err) {
            throw new Error('Unable to parse auth information from Workers KV');
        }

        const { access_token: accessToken, id_token: idToken } = kvStored;
        const userInfo = JSON.parse(decodeJWT(idToken));
        return { accessToken, idToken, userInfo };
    }
    return {};
};

// Authorize request
const authorize = async event => {
    const authorization = await verify(event);
    if (authorization.accessToken) {
        return [true, { authorization }];
    } else {
        const state = await generateStateParam();
        return [false, { redirectUrl: redirectUrl(state) }];
    }
};

// Handle state hydration
const hydrateState = (state = {}) => ({
    element: el => {
        el.setInnerContent(JSON.stringify(state));
    },
});

// Main login handler
async function loginHandleRequest(event) {
    // Early return if Auth0 is not enabled
    if (!authConfig['enable_auth0_com']) {
        return null;
    }
    
    try {
        let request = event.request;

        const [authorized, { authorization, redirectUrl }] = await authorize(event);

        const url = new URL(event.request.url);
        if (url.pathname === '/auth') {
            const authorizedResponse = await handleRedirect(event);
            if (!authorizedResponse) {
                let redirectHeaders = new Headers();
                redirectHeaders.set('Refresh', `1; url=${auth0Config.logoutUrl}`);
                redirectHeaders.set('Set-cookie', `${cookieKey}=""; HttpOnly; Secure; SameSite=Lax;`);
                return new Response('Unauthorized - Redirecting', { status: 302, headers: redirectHeaders });
            }
            let response = new Response(request.body, {
                request,
                ...authorizedResponse,
            });
            return response;
        }

        if (!authorized) {
            return Response.redirect(redirectUrl);
        }

        if (url.pathname === '/logout') {
            let redirectHeaders = new Headers();
            redirectHeaders.set('Location', `${auth0Config.domain}/v2/logout?client_id=${auth0Config.clientId}&returnTo=${auth0Config.logoutUrl}`);
            redirectHeaders.set('Set-cookie', `${cookieKey}=""; HttpOnly; Secure; SameSite=Lax;`);

            return new Response('', {
                status: 302,
                headers: redirectHeaders
            });
        }

        return null;

    } catch (err) {
        return new Response(err.toString());
    }
}

// Basic auth validation helper
function validateBasicAuth(request, authConfig) {
    const auth = authConfig || {};
    const _auth = request.headers.get('Authorization');
    
    if (!_auth) return false;
    
    try {
        const [received_user, received_pass] = atob(_auth.split(' ').pop()).split(':');
        if (auth.hasOwnProperty(received_user)) {
            return auth[received_user] === received_pass;
        }
    } catch (e) {
        console.error('Basic auth error:', e);
    }
    
    return false;
}

// Create 401 response
function createUnauthorizedResponse(realm = 'Protected') {
    return new Response('Unauthorized', {
        headers: {
            'WWW-Authenticate': `Basic realm="${realm}"`,
            'content-type': 'text/html;charset=UTF-8'
        },
        status: 401
    });
}

export {
    loginHandleRequest,
    authorize,
    verify,
    validateBasicAuth,
    createUnauthorizedResponse,
    cookieKey,
    generateStateParam,
    handleRedirect,
    decodeJWT,
    validateToken
};
