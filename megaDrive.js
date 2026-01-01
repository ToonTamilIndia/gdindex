// Mega.nz Drive Handler - Based on mega.py implementation
// Supports: Account login + Public folder links
import { megaConfig } from './config.js';
import { not_found } from './templates.js';

const MEGA_API_URL = 'https://g.api.mega.co.nz/cs';

// ===================== PURE AES-ECB IMPLEMENTATION =====================
class AES_ECB {
    constructor(key) {
        this.sbox = new Uint8Array([
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        ]);
        
        this.sboxInv = new Uint8Array([
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        ]);
        
        this.rcon = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);
        this.roundKeys = this.expandKey(key);
    }
    
    expandKey(key) {
        const keyWords = new Uint32Array(44);
        for (let i = 0; i < 4; i++) {
            keyWords[i] = ((key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3]) >>> 0;
        }
        for (let i = 4; i < 44; i++) {
            let temp = keyWords[i - 1];
            if (i % 4 === 0) {
                temp = ((temp << 8) | (temp >>> 24)) >>> 0;
                temp = ((this.sbox[(temp >>> 24) & 0xff] << 24) |
                        (this.sbox[(temp >>> 16) & 0xff] << 16) |
                        (this.sbox[(temp >>> 8) & 0xff] << 8) |
                        this.sbox[temp & 0xff]) >>> 0;
                temp = (temp ^ (this.rcon[i/4 - 1] << 24)) >>> 0;
            }
            keyWords[i] = (keyWords[i - 4] ^ temp) >>> 0;
        }
        return keyWords;
    }
    
    gmul(a, b) {
        let p = 0;
        for (let i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            const hiBit = a & 0x80;
            a = (a << 1) & 0xff;
            if (hiBit) a ^= 0x1b;
            b >>>= 1;
        }
        return p;
    }
    
    idx(row, col) { return row + 4 * col; }
    
    addRoundKey(s, round) {
        for (let col = 0; col < 4; col++) {
            const w = this.roundKeys[round * 4 + col];
            s[this.idx(0, col)] ^= (w >>> 24) & 0xff;
            s[this.idx(1, col)] ^= (w >>> 16) & 0xff;
            s[this.idx(2, col)] ^= (w >>> 8) & 0xff;
            s[this.idx(3, col)] ^= w & 0xff;
        }
    }
    
    subBytes(s) { for (let i = 0; i < 16; i++) s[i] = this.sbox[s[i]]; }
    invSubBytes(s) { for (let i = 0; i < 16; i++) s[i] = this.sboxInv[s[i]]; }
    
    shiftRows(s) {
        let t = s[this.idx(1, 0)];
        s[this.idx(1, 0)] = s[this.idx(1, 1)]; s[this.idx(1, 1)] = s[this.idx(1, 2)];
        s[this.idx(1, 2)] = s[this.idx(1, 3)]; s[this.idx(1, 3)] = t;
        t = s[this.idx(2, 0)]; s[this.idx(2, 0)] = s[this.idx(2, 2)]; s[this.idx(2, 2)] = t;
        t = s[this.idx(2, 1)]; s[this.idx(2, 1)] = s[this.idx(2, 3)]; s[this.idx(2, 3)] = t;
        t = s[this.idx(3, 3)]; s[this.idx(3, 3)] = s[this.idx(3, 2)];
        s[this.idx(3, 2)] = s[this.idx(3, 1)]; s[this.idx(3, 1)] = s[this.idx(3, 0)]; s[this.idx(3, 0)] = t;
    }
    
    invShiftRows(s) {
        let t = s[this.idx(1, 3)];
        s[this.idx(1, 3)] = s[this.idx(1, 2)]; s[this.idx(1, 2)] = s[this.idx(1, 1)];
        s[this.idx(1, 1)] = s[this.idx(1, 0)]; s[this.idx(1, 0)] = t;
        t = s[this.idx(2, 0)]; s[this.idx(2, 0)] = s[this.idx(2, 2)]; s[this.idx(2, 2)] = t;
        t = s[this.idx(2, 1)]; s[this.idx(2, 1)] = s[this.idx(2, 3)]; s[this.idx(2, 3)] = t;
        t = s[this.idx(3, 0)]; s[this.idx(3, 0)] = s[this.idx(3, 1)];
        s[this.idx(3, 1)] = s[this.idx(3, 2)]; s[this.idx(3, 2)] = s[this.idx(3, 3)]; s[this.idx(3, 3)] = t;
    }
    
    mixColumns(s) {
        for (let col = 0; col < 4; col++) {
            const a = s[this.idx(0, col)], b = s[this.idx(1, col)];
            const c = s[this.idx(2, col)], d = s[this.idx(3, col)];
            s[this.idx(0, col)] = this.gmul(a,2) ^ this.gmul(b,3) ^ c ^ d;
            s[this.idx(1, col)] = a ^ this.gmul(b,2) ^ this.gmul(c,3) ^ d;
            s[this.idx(2, col)] = a ^ b ^ this.gmul(c,2) ^ this.gmul(d,3);
            s[this.idx(3, col)] = this.gmul(a,3) ^ b ^ c ^ this.gmul(d,2);
        }
    }
    
    invMixColumns(s) {
        for (let col = 0; col < 4; col++) {
            const a = s[this.idx(0, col)], b = s[this.idx(1, col)];
            const c = s[this.idx(2, col)], d = s[this.idx(3, col)];
            s[this.idx(0, col)] = this.gmul(a,0x0e) ^ this.gmul(b,0x0b) ^ this.gmul(c,0x0d) ^ this.gmul(d,0x09);
            s[this.idx(1, col)] = this.gmul(a,0x09) ^ this.gmul(b,0x0e) ^ this.gmul(c,0x0b) ^ this.gmul(d,0x0d);
            s[this.idx(2, col)] = this.gmul(a,0x0d) ^ this.gmul(b,0x09) ^ this.gmul(c,0x0e) ^ this.gmul(d,0x0b);
            s[this.idx(3, col)] = this.gmul(a,0x0b) ^ this.gmul(b,0x0d) ^ this.gmul(c,0x09) ^ this.gmul(d,0x0e);
        }
    }
    
    encrypt(block) {
        const s = new Uint8Array(block);
        this.addRoundKey(s, 0);
        for (let round = 1; round <= 9; round++) {
            this.subBytes(s); this.shiftRows(s); this.mixColumns(s); this.addRoundKey(s, round);
        }
        this.subBytes(s); this.shiftRows(s); this.addRoundKey(s, 10);
        return s;
    }
    
    decrypt(block) {
        const s = new Uint8Array(block);
        this.addRoundKey(s, 10);
        for (let round = 9; round >= 1; round--) {
            this.invShiftRows(s); this.invSubBytes(s); this.addRoundKey(s, round); this.invMixColumns(s);
        }
        this.invShiftRows(s); this.invSubBytes(s); this.addRoundKey(s, 0);
        return s;
    }
}

// ===================== CRYPTO UTILITIES =====================
class MegaCrypto {
    static base64UrlDecode(data) {
        data = data.replace(/-/g, '+').replace(/_/g, '/');
        const pad = (4 - data.length % 4) % 4;
        data += '='.repeat(pad);
        try {
            const binary = atob(data);
            return Uint8Array.from(binary, c => c.charCodeAt(0));
        } catch {
            return new Uint8Array(0);
        }
    }

    static base64UrlEncode(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Convert bytes to a32 (big-endian unsigned 32-bit integers)
    static strToA32(bytes) {
        if (typeof bytes === 'string') bytes = new TextEncoder().encode(bytes);
        // Pad to multiple of 4
        if (bytes.length % 4) {
            const padded = new Uint8Array(Math.ceil(bytes.length / 4) * 4);
            padded.set(bytes);
            bytes = padded;
        }
        const a32 = [];
        for (let i = 0; i < bytes.length; i += 4) {
            a32.push(((bytes[i] << 24) | (bytes[i+1] << 16) | (bytes[i+2] << 8) | bytes[i+3]) >>> 0);
        }
        return a32;
    }

    // Convert a32 to bytes (big-endian)
    static a32ToStr(a32) {
        const bytes = new Uint8Array(a32.length * 4);
        for (let i = 0; i < a32.length; i++) {
            bytes[i*4] = (a32[i] >>> 24) & 0xff;
            bytes[i*4+1] = (a32[i] >>> 16) & 0xff;
            bytes[i*4+2] = (a32[i] >>> 8) & 0xff;
            bytes[i*4+3] = a32[i] & 0xff;
        }
        return bytes;
    }

    static base64ToA32(s) { return this.strToA32(this.base64UrlDecode(s)); }
    static a32ToBase64(a32) { return this.base64UrlEncode(this.a32ToStr(a32)); }

    // AES-ECB decrypt using pure JS implementation
    static aesEcbDecrypt(data, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        const result = new Uint8Array(data.length);
        
        for (let i = 0; i < data.length; i += 16) {
            const block = data.slice(i, Math.min(i + 16, data.length));
            if (block.length === 16) {
                result.set(aes.decrypt(block), i);
            } else {
                // Pad last block if needed
                const padded = new Uint8Array(16);
                padded.set(block);
                result.set(aes.decrypt(padded).slice(0, block.length), i);
            }
        }
        return result;
    }
    
    // AES-CBC decrypt with zero IV using pure JS
    static aesCbcDecrypt(data, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        const result = new Uint8Array(data.length);
        let prevCipher = new Uint8Array(16); // Zero IV
        
        for (let i = 0; i < data.length; i += 16) {
            const block = data.slice(i, i + 16);
            if (block.length === 16) {
                const decrypted = aes.decrypt(block);
                for (let j = 0; j < 16; j++) result[i + j] = decrypted[j] ^ prevCipher[j];
                prevCipher = new Uint8Array(block);
            }
        }
        return result;
    }

    // Decrypt key (AES-ECB)
    static decryptKey(encKeyA32, masterKeyA32) {
        const dataBytes = this.a32ToStr(encKeyA32);
        const keyBytes = this.a32ToStr(masterKeyA32);
        const decrypted = this.aesEcbDecrypt(dataBytes, keyBytes);
        return this.strToA32(decrypted);
    }

    // Decrypt node attributes
    static decryptAttr(attr, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const decrypted = this.aesCbcDecrypt(attr, keyBytes);
        const str = new TextDecoder().decode(decrypted).replace(/\0+$/, '');
        
        if (str.startsWith('MEGA{')) {
            try {
                const jsonStr = str.slice(4);
                const endIdx = jsonStr.lastIndexOf('}');
                if (endIdx >= 0) return JSON.parse(jsonStr.slice(0, endIdx + 1));
            } catch {}
        }
        return null;
    }

    // AES-CTR decrypt using WebCrypto (matches Python's Counter.new behavior)
    static async aesCtrDecrypt(data, keyBytes, nonceA32, startBlock = 0) {
        // Build initial counter: [nonce_a32[0], nonce_a32[1], nonce_a32[2], nonce_a32[3]]
        // where nonce_a32 = [fileKey[4], fileKey[5], 0, 0] + startBlock
        const counter = new Uint8Array(16);
        
        // Set the base nonce (first 8 bytes from fileKey[4] and fileKey[5])
        counter[0] = (nonceA32[0] >>> 24) & 0xff;
        counter[1] = (nonceA32[0] >>> 16) & 0xff;
        counter[2] = (nonceA32[0] >>> 8) & 0xff;
        counter[3] = nonceA32[0] & 0xff;
        counter[4] = (nonceA32[1] >>> 24) & 0xff;
        counter[5] = (nonceA32[1] >>> 16) & 0xff;
        counter[6] = (nonceA32[1] >>> 8) & 0xff;
        counter[7] = nonceA32[1] & 0xff;
        
        // Set the block counter (bytes 8-15, big-endian 64-bit)
        const high = Math.floor(startBlock / 0x100000000);
        const low = startBlock >>> 0;
        counter[8] = (high >>> 24) & 0xff;
        counter[9] = (high >>> 16) & 0xff;
        counter[10] = (high >>> 8) & 0xff;
        counter[11] = high & 0xff;
        counter[12] = (low >>> 24) & 0xff;
        counter[13] = (low >>> 16) & 0xff;
        counter[14] = (low >>> 8) & 0xff;
        counter[15] = low & 0xff;
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CTR', counter: counter, length: 64 },
            cryptoKey,
            data
        );
        
        return new Uint8Array(decrypted);
    }

    // Prepare key for legacy Mega authentication
    static async prepareKey(password) {
        const passwordBytes = new TextEncoder().encode(password);
        let pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56];
        
        for (let r = 0; r < 65536; r++) {
            for (let j = 0; j < passwordBytes.length; j += 16) {
                const key = [0, 0, 0, 0];
                for (let i = 0; i < 16; i++) {
                    if (j + i < passwordBytes.length) {
                        key[Math.floor(i / 4)] = ((key[Math.floor(i / 4)] << 8) | passwordBytes[j + i]) >>> 0;
                    }
                }
                const keyBytes = this.a32ToStr(key);
                const pkeyBytes = this.a32ToStr(pkey);
                const encrypted = new AES_ECB(keyBytes).encrypt(pkeyBytes);
                pkey = this.strToA32(encrypted);
            }
        }
        return pkey;
    }

    // Generate string hash for legacy Mega authentication
    static async stringHash(str, aesKey) {
        const strBytes = new TextEncoder().encode(str);
        let s32 = this.strToA32(strBytes);
        let h32 = [0, 0, 0, 0];
        
        for (let i = 0; i < s32.length; i++) {
            h32[i % 4] = (h32[i % 4] ^ s32[i]) >>> 0;
        }
        
        const keyBytes = this.a32ToStr(aesKey);
        const aes = new AES_ECB(keyBytes);
        
        for (let i = 0; i < 16384; i++) {
            const h32Bytes = this.a32ToStr(h32);
            const encrypted = aes.encrypt(h32Bytes);
            h32 = this.strToA32(encrypted);
        }
        
        return this.a32ToBase64([h32[0], h32[2]]);
    }
}

// ===================== MEGA DRIVE CLASS =====================
class MegaDrive {
    constructor(config, order) {
        this.order = order;
        this.root = megaConfig.roots?.[order] || null;
        this.account = megaConfig.accounts?.[order] || megaConfig.accounts?.[0] || null;
        this.url_path_prefix = '/mega' + order + ':';
        
        this.sid = null;
        this.masterKey = null;
        this.sequenceNum = Math.floor(Math.random() * 0xFFFFFFFF);
        
        this.nodes = new Map();
        this.rootNodeId = null;
        this.folderKey = null;
        this.folderHandle = null;
        this.isPublicFolder = false;
        
        this.initialized = false;
    }

    parseFolderLink(link) {
        if (!link) return null;
        
        let match = link.match(/mega\.nz\/folder\/([A-Za-z0-9_-]+)#([A-Za-z0-9_-]+)/);
        if (match) return { handle: match[1], key: match[2] };
        
        match = link.match(/mega\.nz\/#F!([A-Za-z0-9_-]+)!([A-Za-z0-9_-]+)/);
        if (match) return { handle: match[1], key: match[2] };
        
        match = link.match(/mega\.nz\/fm\/([A-Za-z0-9_-]+)/);
        if (match) return { fmPath: match[1], needsLogin: true };
        
        return null;
    }

    async apiRequest(data, params = '') {
        if (this.sid) {
            params += '&sid=' + this.sid;
        }
        
        const finalUrl = MEGA_API_URL + '?id=' + (this.sequenceNum++) + params;
        
        try {
            const res = await fetch(finalUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Array.isArray(data) ? data : [data])
            });
            return await res.json();
        } catch (e) {
            console.error('Mega API error:', e);
            return null;
        }
    }

    async login(email, password) {
        try {
            const saltResp = await this.apiRequest({ a: 'us0', user: email.toLowerCase() });
            
            let passwordAes, userHash;
            
            if (saltResp?.[0]?.s) {
                const userSalt = MegaCrypto.base64ToA32(saltResp[0].s);
                const saltBytes = MegaCrypto.a32ToStr(userSalt);
                
                const keyMaterial = await crypto.subtle.importKey(
                    'raw', new TextEncoder().encode(password),
                    'PBKDF2', false, ['deriveBits']
                );
                const derivedBits = await crypto.subtle.deriveBits(
                    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-512' },
                    keyMaterial, 256
                );
                const pbkdf2Key = new Uint8Array(derivedBits);
                
                passwordAes = MegaCrypto.strToA32(pbkdf2Key.slice(0, 16));
                userHash = MegaCrypto.base64UrlEncode(pbkdf2Key.slice(16, 32));
            } else {
                passwordAes = await MegaCrypto.prepareKey(password);
                userHash = await MegaCrypto.stringHash(email.toLowerCase(), passwordAes);
            }
            
            const loginResp = await this.apiRequest({ a: 'us', user: email.toLowerCase(), uh: userHash });
            
            if (!loginResp?.[0] || typeof loginResp[0] === 'number') {
                console.error('Mega: Login failed', loginResp);
                return false;
            }
            
            const resp = loginResp[0];
            const encryptedMasterKey = MegaCrypto.base64ToA32(resp.k);
            this.masterKey = await MegaCrypto.decryptKey(encryptedMasterKey, passwordAes);
            
            this.sid = resp.tsid || resp.csid;
            return true;
        } catch (e) {
            console.error('Mega: Login error:', e);
            return false;
        }
    }

    async init() {
        if (this.initialized) return;
        
        const parsed = this.root?.link ? this.parseFolderLink(this.root.link) : null;
        
        if (parsed?.needsLogin || !parsed) {
            if (this.account?.email && this.account?.password) {
                const loggedIn = await this.login(this.account.email, this.account.password);
                if (loggedIn) {
                    await this.loadAccountFiles(parsed?.fmPath);
                }
            }
        } else if (parsed?.handle && parsed?.key) {
            this.isPublicFolder = true;
            this.folderHandle = parsed.handle;
            this.folderKey = MegaCrypto.base64ToA32(parsed.key);
            await this.loadPublicFolder();
        }
        
        this.initialized = true;
    }

    async loadAccountFiles(fmPath = null) {
        const resp = await this.apiRequest([{ a: 'f', c: 1 }]);
        
        if (!resp?.[0]?.f) return;
        
        for (const file of resp[0].f) {
            await this.processNode(file, false);
        }
        
        if (fmPath && this.nodes.has(fmPath)) {
            this.rootNodeId = fmPath;
        }
    }

    async loadPublicFolder() {
        const resp = await this.apiRequest([{ a: 'f', c: 1, r: 1, ca: 1 }], '&n=' + this.folderHandle);

        if (!resp?.[0] || typeof resp[0] === 'number') {
            const errors = {
                '-2': 'Invalid arguments',
                '-9': 'Object not found', 
                '-11': 'Access denied',
                '-14': 'Invalid key',
                '-16': 'Blocked',
                '-17': 'Over quota'
            };
            console.error('Mega: API error', resp?.[0], errors[String(resp?.[0])] || 'Unknown');
            return;
        }
        
        if (!resp[0].f) return;
        
        const files = resp[0].f;
        let foundRoot = false;
        
        for (const file of files) {
            if (file.t === 1 && !foundRoot) {
                const parentExists = files.some(f => f.h === file.p);
                if (!parentExists) {
                    this.rootNodeId = file.h;
                    foundRoot = true;
                }
            }
            await this.processNode(file, true);
        }
        
        if (!this.rootNodeId) {
            for (const [id, node] of this.nodes) {
                if (node.type === 1) {
                    this.rootNodeId = id;
                    break;
                }
            }
        }
    }

    async processNode(node, isPublic) {
        let name = null;
        let key = null;
        
        if (node.t === 2) {
            this.rootNodeId = node.h;
            name = this.root?.name || 'Cloud Drive';
        } else if (node.t === 3) {
            name = 'Inbox';
        } else if (node.t === 4) {
            name = 'Trash';
        } else if (node.a && node.k) {
            try {
                if (isPublic) {
                    const keyParts = node.k.split(':');
                    const encKeyB64 = keyParts[keyParts.length - 1];
                    const encKeyBytes = MegaCrypto.base64UrlDecode(encKeyB64);
                    const encKey = MegaCrypto.strToA32(encKeyBytes);
                    
                    const decKey = await MegaCrypto.decryptKey(encKey, this.folderKey);
                    key = decKey;
                    
                    let aesKey;
                    if (node.t === 0 && decKey.length >= 8) {
                        aesKey = [
                            (decKey[0] ^ decKey[4]) >>> 0,
                            (decKey[1] ^ decKey[5]) >>> 0,
                            (decKey[2] ^ decKey[6]) >>> 0,
                            (decKey[3] ^ decKey[7]) >>> 0
                        ];
                    } else {
                        aesKey = decKey.slice(0, 4);
                    }
                    
                    const attrBytes = MegaCrypto.base64UrlDecode(node.a);
                    const attrs = await MegaCrypto.decryptAttr(attrBytes, aesKey);
                    if (attrs?.n) name = attrs.n;
                } else if (this.masterKey) {
                    const keyParts = node.k.split('/');
                    for (const part of keyParts) {
                        if (part.includes(':')) {
                            const [, encKeyB64] = part.split(':');
                            const encKey = MegaCrypto.base64ToA32(encKeyB64);
                            const decKey = await MegaCrypto.decryptKey(encKey, this.masterKey);
                            key = decKey;
                            
                            let aesKey;
                            if (node.t === 0 && decKey.length >= 8) {
                                aesKey = [
                                    (decKey[0] ^ decKey[4]) >>> 0,
                                    (decKey[1] ^ decKey[5]) >>> 0,
                                    (decKey[2] ^ decKey[6]) >>> 0,
                                    (decKey[3] ^ decKey[7]) >>> 0
                                ];
                            } else {
                                aesKey = decKey.slice(0, 4);
                            }
                            
                            const attrBytes = MegaCrypto.base64UrlDecode(node.a);
                            const attrs = await MegaCrypto.decryptAttr(attrBytes, aesKey);
                            if (attrs?.n) {
                                name = attrs.n;
                                break;
                            }
                        }
                    }
                }
            } catch (e) {
                console.error('Mega: Error decrypting node', node.h, e.message);
            }
        }
        
        if (!name) name = 'Item_' + node.h;
        
        const nodeInfo = {
            id: node.h,
            name: name,
            parentId: node.p || this.rootNodeId,
            type: node.t,
            size: node.s || 0,
            key: key,
            mimeType: (node.t === 1 || node.t === 2) ? 'application/vnd.google-apps.folder' : this.getMimeType(name),
            modifiedTime: node.ts ? new Date(node.ts * 1000).toISOString() : new Date().toISOString()
        };
        
        this.nodes.set(node.h, nodeInfo);
    }

    getMimeType(name) {
        const ext = (name || '').split('.').pop().toLowerCase();
        const types = {
            mp4: 'video/mp4', mkv: 'video/x-matroska', avi: 'video/x-msvideo', 
            webm: 'video/webm', mov: 'video/quicktime', m4v: 'video/x-m4v',
            ts: 'video/mp2t', m2ts: 'video/mp2t', mts: 'video/mp2t',
            mp3: 'audio/mpeg', flac: 'audio/flac', wav: 'audio/wav', 
            m4a: 'audio/mp4', aac: 'audio/aac', ogg: 'audio/ogg',
            jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', 
            gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
            pdf: 'application/pdf', zip: 'application/zip', 
            rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
            txt: 'text/plain', html: 'text/html', css: 'text/css',
            js: 'application/javascript', json: 'application/json',
            srt: 'application/x-subrip', vtt: 'text/vtt', ass: 'text/x-ass'
        };
        return types[ext] || 'application/octet-stream';
    }

    basicAuthResponse(request) {
        if (!this.root?.auth) return null;
        const auth = this.root.auth;
        const header = request.headers.get('Authorization');
        if (header) {
            try {
                const [user, pass] = atob(header.split(' ').pop()).split(':');
                if (auth[user] === pass) return null;
            } catch {}
        }
        return new Response('Unauthorized', {
            headers: { 'WWW-Authenticate': 'Basic realm="Mega"', 'content-type': 'text/html' },
            status: 401
        });
    }

    async list(path = '/', pageToken = null, pageIndex = 0) {
        if (!this.initialized) await this.init();
        
        let parentId = this.rootNodeId;
        const parts = path.split('/').filter(p => p);
        
        for (const part of parts) {
            let found = false;
            for (const [id, node] of this.nodes) {
                if (node.name === part && node.parentId === parentId && (node.type === 1 || node.type === 2)) {
                    parentId = id;
                    found = true;
                    break;
                }
            }
            if (!found) break;
        }
        
        const files = [];
        
        for (const [id, node] of this.nodes) {
            const isChild = node.parentId === parentId;
            
            if (isChild && id !== this.rootNodeId && node.type !== 2) {
                files.push({
                    id: node.id,
                    name: node.name,
                    mimeType: node.mimeType,
                    size: String(node.size),
                    modifiedTime: node.modifiedTime
                });
            }
        }
        
        files.sort((a, b) => {
            const aIsFolder = a.mimeType === 'application/vnd.google-apps.folder';
            const bIsFolder = b.mimeType === 'application/vnd.google-apps.folder';
            if (aIsFolder && !bIsFolder) return -1;
            if (!aIsFolder && bIsFolder) return 1;
            return a.name.localeCompare(b.name);
        });
        
        return { nextPageToken: null, curPageIndex: pageIndex, data: { files } };
    }

    async file(path) {
        if (!this.initialized) await this.init();
        
        const parts = path.split('/').filter(p => p);
        if (!parts.length) return null;
        
        let parentId = this.rootNodeId;
        
        for (let i = 0; i < parts.length; i++) {
            const part = parts[i];
            const isLast = i === parts.length - 1;
            let found = null;
            
            for (const [id, node] of this.nodes) {
                if (node.name === part && node.parentId === parentId) {
                    if (isLast) {
                        return node;
                    } else if (node.type === 1) {
                        parentId = id;
                        found = node;
                        break;
                    }
                }
            }
            
            if (!found && !isLast) {
                return null;
            }
        }
        
        return this.nodes.get(parts[parts.length - 1]) || null;
    }

    async down(fileId, range = '', inline = false) {
    if (!this.initialized) await this.init();
    
    const node = this.nodes.get(fileId);
    if (!node) {
        return new Response(not_found, { status: 404, headers: { 'content-type': 'text/html' } });
    }
    
    try {
        let params = '';
        let reqBody;
        
        if (this.isPublicFolder) {
            params = '&n=' + this.folderHandle;
            reqBody = [{ a: 'g', g: 1, n: fileId }];
        } else {
            reqBody = [{ a: 'g', g: 1, n: fileId }];
        }
        
        const resp = await this.apiRequest(reqBody, params);
        
        if (!resp?.[0]?.g) {
            console.error('Mega: No download URL', resp);
            return new Response('File not accessible', { status: 404 });
        }
        
        const downloadUrl = resp[0].g;
        const fileSize = resp[0].s || node.size;
        
        // Parse range - ALWAYS use range internally (even if client didn't request one)
        // This is a workaround for Mega's 509 error on full file downloads
        let startByte = 0;
        let endByte = fileSize - 1;
        let clientRequestedRange = false;
        
        if (range && range.startsWith('bytes=')) {
            const rangeParts = range.replace('bytes=', '').split('-');
            startByte = parseInt(rangeParts[0]) || 0;
            endByte = rangeParts[1] ? parseInt(rangeParts[1]) : fileSize - 1;
            clientRequestedRange = true;
        }
        // If no range requested, we still use 0 to fileSize-1 but treat it as a range request
        
        // Clamp endByte
        if (endByte >= fileSize) endByte = fileSize - 1;
        if (startByte > endByte) startByte = endByte;
        
        const contentLength = endByte - startByte + 1;
        
        const fileKey = node.key;
        
        // Handle unencrypted files (no valid key)
        if (!fileKey || fileKey.length < 8) {
            // ALWAYS use Range header to avoid Mega 509 errors
            const fetchHeaders = { 
                'Range': `bytes=${startByte}-${endByte}` 
            };
            const fileResp = await fetch(downloadUrl, { headers: fetchHeaders });
            
            if (!fileResp.ok && fileResp.status !== 206) {
                console.error('Mega: Fetch failed', fileResp.status);
                return new Response('Fetch failed', { status: 502 });
            }
            
            // Always return 206 with Content-Range
            return new Response(fileResp.body, {
                status: 206,
                headers: {
                    'Content-Type': node.mimeType,
                    'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(node.name)}`,
                    'Content-Length': String(contentLength),
                    'Content-Range': `bytes ${startByte}-${endByte}/${fileSize}`,
                    'Accept-Ranges': 'bytes',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
                    'Access-Control-Allow-Headers': 'Range',
                    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges'
                }
            });
        }
        
        // Extract AES key: XOR first and second half of file key
        const aesKey = [
            (fileKey[0] ^ fileKey[4]) >>> 0,
            (fileKey[1] ^ fileKey[5]) >>> 0,
            (fileKey[2] ^ fileKey[6]) >>> 0,
            (fileKey[3] ^ fileKey[7]) >>> 0
        ];
        
        const keyBytes = new Uint8Array(16);
        for (let i = 0; i < 4; i++) {
            keyBytes[i*4] = (aesKey[i] >>> 24) & 0xff;
            keyBytes[i*4+1] = (aesKey[i] >>> 16) & 0xff;
            keyBytes[i*4+2] = (aesKey[i] >>> 8) & 0xff;
            keyBytes[i*4+3] = aesKey[i] & 0xff;
        }
        
        // Build base nonce from fileKey[4] and fileKey[5]
        const baseNonce = new Uint8Array(8);
        baseNonce[0] = (fileKey[4] >>> 24) & 0xff;
        baseNonce[1] = (fileKey[4] >>> 16) & 0xff;
        baseNonce[2] = (fileKey[4] >>> 8) & 0xff;
        baseNonce[3] = fileKey[4] & 0xff;
        baseNonce[4] = (fileKey[5] >>> 24) & 0xff;
        baseNonce[5] = (fileKey[5] >>> 16) & 0xff;
        baseNonce[6] = (fileKey[5] >>> 8) & 0xff;
        baseNonce[7] = fileKey[5] & 0xff;
        
        // Align to 16-byte blocks for CTR mode
        const blockStart = Math.floor(startByte / 16) * 16;
        const blockOffset = startByte - blockStart;
        const startBlockNum = Math.floor(blockStart / 16);
        
        // ALWAYS fetch with Range header to avoid Mega 509 errors
        const fetchHeaders = {
            'Range': `bytes=${blockStart}-${endByte}`
        };
        
        const fileResp = await fetch(downloadUrl, { headers: fetchHeaders });
        
        if (!fileResp.ok && fileResp.status !== 206) {
            console.error('Mega: Fetch failed', fileResp.status);
            return new Response('Fetch failed', { status: 502 });
        }
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes,
            { name: 'AES-CTR' },
            false, ['decrypt']
        );
        
        // Build counter for a specific block number
        const buildCounter = (blockNum) => {
            const ctr = new Uint8Array(16);
            ctr.set(baseNonce, 0);
            const high = Math.floor(blockNum / 0x100000000);
            const low = blockNum >>> 0;
            ctr[8] = (high >>> 24) & 0xff;
            ctr[9] = (high >>> 16) & 0xff;
            ctr[10] = (high >>> 8) & 0xff;
            ctr[11] = high & 0xff;
            ctr[12] = (low >>> 24) & 0xff;
            ctr[13] = (low >>> 16) & 0xff;
            ctr[14] = (low >>> 8) & 0xff;
            ctr[15] = low & 0xff;
            return ctr;
        };
        
        // Streaming decryption with proper counter management
        let currentBlockNum = startBlockNum;
        let pendingData = new Uint8Array(0);
        let skipBytes = blockOffset;
        
        const transformStream = new TransformStream({
            transform: async (chunk, controller) => {
                try {
                    const newPending = new Uint8Array(pendingData.length + chunk.length);
                    newPending.set(pendingData);
                    newPending.set(chunk, pendingData.length);
                    pendingData = newPending;
                    
                    const completeBytes = Math.floor(pendingData.length / 16) * 16;
                    
                    if (completeBytes > 0) {
                        const toDecrypt = pendingData.slice(0, completeBytes);
                        pendingData = pendingData.slice(completeBytes);
                        
                        const counter = buildCounter(currentBlockNum);
                        currentBlockNum += toDecrypt.length / 16;
                        
                        const decryptedBuffer = await crypto.subtle.decrypt(
                            { name: 'AES-CTR', counter: counter, length: 64 },
                            cryptoKey,
                            toDecrypt
                        );
                        
                        let decrypted = new Uint8Array(decryptedBuffer);
                        
                        if (skipBytes > 0) {
                            decrypted = decrypted.slice(skipBytes);
                            skipBytes = 0;
                        }
                        
                        controller.enqueue(decrypted);
                    }
                } catch (e) {
                    console.error('Transform error:', e);
                    controller.error(e);
                }
            },
            flush: async (controller) => {
                try {
                    if (pendingData.length > 0) {
                        const padded = new Uint8Array(16);
                        padded.set(pendingData);
                        
                        const counter = buildCounter(currentBlockNum);
                        
                        const decryptedBuffer = await crypto.subtle.decrypt(
                            { name: 'AES-CTR', counter: counter, length: 64 },
                            cryptoKey,
                            padded
                        );
                        
                        let decrypted = new Uint8Array(decryptedBuffer).slice(0, pendingData.length);
                        
                        if (skipBytes > 0) {
                            decrypted = decrypted.slice(skipBytes);
                        }
                        
                        if (decrypted.length > 0) {
                            controller.enqueue(decrypted);
                        }
                    }
                } catch (e) {
                    console.error('Flush error:', e);
                }
            }
        });
        
        const decryptedStream = fileResp.body.pipeThrough(transformStream);
        
        const isMedia = node.mimeType.startsWith('video/') || node.mimeType.startsWith('audio/');
        const disposition = (inline || isMedia) ? 'inline' : 'attachment';
        
        // ALWAYS respond with 206 and Content-Range to work around Mega limitations
        const respHeaders = {
            'Content-Type': node.mimeType,
            'Content-Disposition': `${disposition}; filename*=UTF-8''${encodeURIComponent(node.name)}`,
            'Accept-Ranges': 'bytes',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Headers': 'Range',
            'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges',
            'Content-Length': String(contentLength),
            'Content-Range': `bytes ${startByte}-${endByte}/${fileSize}`
        };
        
        // Always return 206 Partial Content
        return new Response(decryptedStream, { status: 206, headers: respHeaders });
        
    } catch (e) {
        console.error('Mega: Download error:', e);
        return new Response('Download error: ' + e.message, { status: 500 });
    }
}

    async search(keyword, pageToken = null, pageIndex = 0) {
        if (!this.initialized) await this.init();
        
        const files = [];
        const lower = keyword.toLowerCase();
        
        for (const [id, node] of this.nodes) {
            if (node.name.toLowerCase().includes(lower) && node.type === 0) {
                files.push({
                    id: node.id,
                    name: node.name,
                    mimeType: node.mimeType,
                    size: String(node.size),
                    modifiedTime: node.modifiedTime
                });
            }
        }
        
        return { nextPageToken: null, curPageIndex: pageIndex, data: { files } };
    }
}

async function initMegaDrives() {
    const drives = [];
    if (megaConfig.enabled && megaConfig.roots?.length) {
        for (let i = 0; i < megaConfig.roots.length; i++) {
            const drive = new MegaDrive(megaConfig, i);
            await drive.init();
            drives.push(drive);
        }
    }
    return drives;
}

export { MegaDrive, MegaCrypto, initMegaDrives };