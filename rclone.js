// Rclone Configuration Parser and Handler
// Supports parsing rclone.conf files for Google Drive and Mega.nz remotes

import { authConfig, megaConfig } from './config.js';

/**
 * Parse rclone.conf file content into structured configuration
 * @param {string} configContent - The content of rclone.conf file
 * @returns {Object} Parsed remotes with their configurations
 */
function parseRcloneConfig(configContent) {
    const remotes = {};
    let currentRemote = null;
    
    const lines = configContent.split('\n');
    
    for (let line of lines) {
        line = line.trim();
        
        // Skip empty lines and comments
        if (!line || line.startsWith('#') || line.startsWith(';')) {
            continue;
        }
        
        // Check for remote section header [remotename]
        const sectionMatch = line.match(/^\[(.+)\]$/);
        if (sectionMatch) {
            currentRemote = sectionMatch[1];
            remotes[currentRemote] = {
                name: currentRemote,
                type: null,
                config: {}
            };
            continue;
        }
        
        // Parse key = value pairs
        if (currentRemote) {
            const kvMatch = line.match(/^([^=]+)=(.*)$/);
            if (kvMatch) {
                const key = kvMatch[1].trim();
                let value = kvMatch[2].trim();
                
                // Remove quotes if present
                if ((value.startsWith('"') && value.endsWith('"')) ||
                    (value.startsWith("'") && value.endsWith("'"))) {
                    value = value.slice(1, -1);
                }
                
                if (key === 'type') {
                    remotes[currentRemote].type = value;
                } else {
                    remotes[currentRemote].config[key] = value;
                }
            }
        }
    }
    
    return remotes;
}

/**
 * Convert rclone Google Drive remote to authConfig root format
 * @param {Object} remote - Parsed rclone remote
 * @param {number} index - Index for the root
 * @returns {Object} authConfig root object
 */
function rcloneToGoogleDriveRoot(remote, index) {
    const config = remote.config;
    
    return {
        id: config.root_folder_id || config.team_drive || 'root',
        name: remote.name,
        protect_file_link: false,
        // Auth can be added separately via dashboard
    };
}

/**
 * Convert rclone Mega remote to megaConfig root format
 * @param {Object} remote - Parsed rclone remote
 * @param {number} index - Index for the root
 * @returns {Object} megaConfig root object
 */
function rcloneToMegaRoot(remote, index) {
    const config = remote.config;
    
    return {
        id: `mega_${index}`,
        name: remote.name,
        public: true,
        email: config.user || '',
        password: config.pass ? decodeRclonePassword(config.pass) : ''
    };
}

/**
 * Decode rclone obscured password
 * Rclone uses a simple obscure mechanism (not encryption)
 * @param {string} obscured - The obscured password from rclone
 * @returns {string} Decoded password
 */
function decodeRclonePassword(obscured) {
    // Rclone obscure key (public, not for security)
    const key = [
        0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d,
        0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
        0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb,
        0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38
    ];
    
    try {
        // Base64 decode
        const decoded = atob(obscured);
        const bytes = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            bytes[i] = decoded.charCodeAt(i);
        }
        
        // XOR with key
        const result = [];
        for (let i = 0; i < bytes.length; i++) {
            result.push(bytes[i] ^ key[i % key.length]);
        }
        
        return String.fromCharCode(...result);
    } catch (e) {
        console.error('Failed to decode rclone password:', e);
        return obscured; // Return as-is if decode fails
    }
}

/**
 * Extract Google Drive OAuth tokens from rclone config
 * @param {Object} remote - Parsed rclone remote
 * @returns {Object} OAuth token configuration
 */
function extractGoogleDriveTokens(remote) {
    const config = remote.config;
    const tokens = {
        client_id: config.client_id || '',
        client_secret: config.client_secret || '',
        refresh_token: '',
        access_token: '',
        service_account: false,
        service_account_json: null
    };
    
    // Parse token JSON if present
    if (config.token) {
        try {
            const tokenData = JSON.parse(config.token);
            tokens.access_token = tokenData.access_token || '';
            tokens.refresh_token = tokenData.refresh_token || '';
        } catch (e) {
            console.error('Failed to parse token JSON:', e);
        }
    }
    
    // Check for service account
    if (config.service_account_file) {
        tokens.service_account = true;
        // Service account JSON would need to be loaded separately
    }
    
    return tokens;
}

/**
 * Import rclone.conf and merge with existing configuration
 * @param {string} configContent - Content of rclone.conf
 * @returns {Object} Merged configuration object
 */
function importRcloneConfig(configContent) {
    const remotes = parseRcloneConfig(configContent);
    const result = {
        googleDriveRoots: [],
        megaRoots: [],
        megaAccounts: [],
        googleDriveTokens: null,
        errors: []
    };
    
    let gdIndex = authConfig.roots.length;
    let megaIndex = megaConfig.roots ? megaConfig.roots.length : 0;
    
    for (const [name, remote] of Object.entries(remotes)) {
        try {
            switch (remote.type) {
                case 'drive':
                    // Google Drive remote
                    const gdRoot = rcloneToGoogleDriveRoot(remote, gdIndex);
                    result.googleDriveRoots.push(gdRoot);
                    
                    // Extract tokens from first Google Drive remote
                    if (!result.googleDriveTokens) {
                        result.googleDriveTokens = extractGoogleDriveTokens(remote);
                    }
                    gdIndex++;
                    break;
                    
                case 'mega':
                    // Mega.nz remote
                    const megaRoot = rcloneToMegaRoot(remote, megaIndex);
                    result.megaRoots.push(megaRoot);
                    
                    // Add Mega account
                    if (remote.config.user) {
                        result.megaAccounts.push({
                            email: remote.config.user,
                            password: remote.config.pass ? 
                                decodeRclonePassword(remote.config.pass) : ''
                        });
                    }
                    megaIndex++;
                    break;
                    
                case 'crypt':
                    // Encrypted remote - note for user
                    result.errors.push(
                        `Remote "${name}" is encrypted (crypt). Encrypted remotes are not directly supported.`
                    );
                    break;
                    
                case 'alias':
                    // Alias remote - skip with note
                    result.errors.push(
                        `Remote "${name}" is an alias. Please use the original remote.`
                    );
                    break;
                    
                default:
                    result.errors.push(
                        `Remote "${name}" uses unsupported type "${remote.type}". Only 'drive' and 'mega' are supported.`
                    );
            }
        } catch (e) {
            result.errors.push(`Error processing remote "${name}": ${e.message}`);
        }
    }
    
    return result;
}

/**
 * Generate rclone.conf content from current configuration
 * @returns {string} rclone.conf formatted content
 */
function exportToRcloneConfig() {
    let config = '# Generated by GDIndex\n# https://github.com/GoogleDriveIndex/Google-Drive-Index\n\n';
    
    // Export Google Drive roots
    authConfig.roots.forEach((root, index) => {
        config += `[gdindex_drive_${index}]\n`;
        config += `type = drive\n`;
        if (root.id && root.id !== 'root') {
            if (root.id.startsWith('0A')) {
                config += `team_drive = ${root.id}\n`;
            } else {
                config += `root_folder_id = ${root.id}\n`;
            }
        }
        if (authConfig.client_id) {
            config += `client_id = ${authConfig.client_id}\n`;
        }
        if (authConfig.client_secret) {
            config += `client_secret = ${authConfig.client_secret}\n`;
        }
        if (authConfig.refresh_token) {
            const token = JSON.stringify({
                access_token: authConfig.accessToken || '',
                refresh_token: authConfig.refresh_token,
                token_type: 'Bearer',
                expiry: new Date(Date.now() + 3600000).toISOString()
            });
            config += `token = ${token}\n`;
        }
        config += `\n`;
    });
    
    // Export Mega roots
    if (megaConfig.enabled && megaConfig.accounts) {
        megaConfig.accounts.forEach((account, index) => {
            config += `[gdindex_mega_${index}]\n`;
            config += `type = mega\n`;
            if (account.email) {
                config += `user = ${account.email}\n`;
            }
            // Note: Password should be obscured in real rclone config
            config += `\n`;
        });
    }
    
    return config;
}

/**
 * Validate rclone configuration
 * @param {string} configContent - Content of rclone.conf
 * @returns {Object} Validation result with isValid and errors
 */
function validateRcloneConfig(configContent) {
    const result = {
        isValid: true,
        errors: [],
        warnings: [],
        remotes: []
    };
    
    try {
        const remotes = parseRcloneConfig(configContent);
        
        if (Object.keys(remotes).length === 0) {
            result.isValid = false;
            result.errors.push('No remotes found in configuration');
            return result;
        }
        
        for (const [name, remote] of Object.entries(remotes)) {
            result.remotes.push({
                name,
                type: remote.type,
                supported: ['drive', 'mega'].includes(remote.type)
            });
            
            if (!remote.type) {
                result.errors.push(`Remote "${name}" has no type specified`);
                result.isValid = false;
            }
            
            if (remote.type === 'drive') {
                if (!remote.config.token && !remote.config.service_account_file) {
                    result.warnings.push(
                        `Remote "${name}" has no token or service account configured`
                    );
                }
            }
            
            if (remote.type === 'mega') {
                if (!remote.config.user) {
                    result.warnings.push(`Remote "${name}" has no user configured`);
                }
            }
        }
    } catch (e) {
        result.isValid = false;
        result.errors.push(`Parse error: ${e.message}`);
    }
    
    return result;
}

// Sample rclone.conf template
const RCLONE_CONFIG_TEMPLATE = `# Rclone Configuration Template for GDIndex
# Copy this file to rclone.conf and fill in your details

# Google Drive Remote Example
[my_gdrive]
type = drive
client_id = YOUR_CLIENT_ID.apps.googleusercontent.com
client_secret = YOUR_CLIENT_SECRET
scope = drive
token = {"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"..."}
# For Shared Drive, add:
# team_drive = SHARED_DRIVE_ID
# For specific folder, add:
# root_folder_id = FOLDER_ID

# Google Drive with Service Account
[my_gdrive_sa]
type = drive
scope = drive
service_account_file = /path/to/service-account.json
team_drive = SHARED_DRIVE_ID

# Mega.nz Remote Example
[my_mega]
type = mega
user = your@email.com
pass = YOUR_OBSCURED_PASSWORD

# To get obscured password, run: rclone obscure YOUR_PASSWORD
`;

export {
    parseRcloneConfig,
    importRcloneConfig,
    exportToRcloneConfig,
    validateRcloneConfig,
    rcloneToGoogleDriveRoot,
    rcloneToMegaRoot,
    decodeRclonePassword,
    extractGoogleDriveTokens,
    RCLONE_CONFIG_TEMPLATE
};
