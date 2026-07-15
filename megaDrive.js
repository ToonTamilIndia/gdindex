// Mega.nz Drive Handler — Based on mega.py implementation
// Supports: Account login + Public folder links

import { megaConfig } from './config.js';
import { not_found } from './templates.js';

const MEGA_API_URL = 'https://g.api.mega.co.nz/cs';

// Polyfills for Node test environment
if (typeof atob === 'undefined') {
    global.atob = (s) => Buffer.from(s, 'base64').toString('binary');
    global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
}
if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    const { webcrypto } = await import('node:crypto').catch(()=>({}));
    if (webcrypto) global.crypto = webcrypto;
}

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
    static strToA32(bytes) {
        if (typeof bytes === 'string') bytes = new TextEncoder().encode(bytes);
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
    static a32ToStr(a32) {
        const bytes = new Uint8Array(a32.length * 4);
        for (let i = 0; i < a32.length; i++) {
            bytes[i*4]   = (a32[i] >>> 24) & 0xff;
            bytes[i*4+1] = (a32[i] >>> 16) & 0xff;
            bytes[i*4+2] = (a32[i] >>> 8)  & 0xff;
            bytes[i*4+3] =  a32[i]         & 0xff;
        }
        return bytes;
    }
    static base64ToA32(s) { return this.strToA32(this.base64UrlDecode(s)); }
    static a32ToBase64(a32) { return this.base64UrlEncode(this.a32ToStr(a32)); }

    // -------- AES-ECB encrypt --------
    static aesEcbEncrypt(data, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 16) {
            const block = data.slice(i, Math.min(i + 16, data.length));
            if (block.length === 16) {
                result.set(aes.encrypt(block), i);
            } else {
                const padded = new Uint8Array(16);
                padded.set(block);
                result.set(aes.encrypt(padded).subarray(0, block.length), i);
            }
        }
        return result;
    }
    // -------- AES-ECB decrypt --------
    static aesEcbDecrypt(data, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 16) {
            const block = data.slice(i, Math.min(i + 16, data.length));
            if (block.length === 16) {
                result.set(aes.decrypt(block), i);
            } else {
                const padded = new Uint8Array(16);
                padded.set(block);
                result.set(aes.decrypt(padded).subarray(0, block.length), i);
            }
        }
        return result;
    }
    // -------- AES-CBC decrypt (zero IV) --------
    static aesCbcDecrypt(data, key) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        const result = new Uint8Array(data.length);
        let prevCipher = new Uint8Array(16);
        for (let i = 0; i < data.length; i += 16) {
            const block = data.slice(i, i + 16);
            if (block.length === 16) {
                const decrypted = aes.decrypt(block);
                for (let j = 0; j < 16; j++) result[i + j] = decrypted[j] ^ prevCipher[j];
                prevCipher = block.slice();
            }
        }
        return result;
    }
    static aesCbcEncrypt(data, key, iv = new Uint8Array(16)) {
        const keyBytes = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const aes = new AES_ECB(keyBytes.slice(0, 16));
        // Pad to 16-byte boundary with zeros (MEGA attribute convention)
        const paddedLen = Math.ceil(data.length / 16) * 16 || 16;
        const padded = new Uint8Array(paddedLen);
        padded.set(data);
        const result = new Uint8Array(paddedLen);
        let prev = new Uint8Array(iv);
        for (let i = 0; i < paddedLen; i += 16) {
            const block = padded.slice(i, i + 16);
            const mixed = new Uint8Array(16);
            for (let j = 0; j < 16; j++) mixed[j] = block[j] ^ prev[j];
            const encrypted = aes.encrypt(mixed);
            result.set(encrypted, i);
            prev = encrypted;
        }
        return result;
    }
    static randomA32(length) {
        const values = new Uint32Array(length);
        crypto.getRandomValues(values);
        return Array.from(values, v => v >>> 0);
    }
    // -------- Key helpers --------
    static encryptKey(keyA32, masterKeyA32) {
        const dataBytes = this.a32ToStr(keyA32);
        const keyBytes = this.a32ToStr(masterKeyA32);
        const encrypted = this.aesEcbEncrypt(dataBytes, keyBytes);
        return this.strToA32(encrypted);
    }
    static decryptKey(encKeyA32, masterKeyA32) {
        const dataBytes = this.a32ToStr(encKeyA32);
        const keyBytes  = this.a32ToStr(masterKeyA32);
        const decrypted = this.aesEcbDecrypt(dataBytes, keyBytes);
        return this.strToA32(decrypted);
    }
    static encryptAttr(attrs, key) {
        const bytes = new TextEncoder().encode('MEGA' + JSON.stringify(attrs));
        const padded = new Uint8Array(Math.ceil(bytes.length / 16) * 16 || 16);
        padded.set(bytes);
        return this.aesCbcEncrypt(padded, key);
    }
    static decryptAttr(attr, key) {
        const keyBytes  = key instanceof Uint8Array ? key : this.a32ToStr(key);
        const decrypted = this.aesCbcDecrypt(attr, keyBytes);
        const str = new TextDecoder().decode(decrypted).replace(/\0+$/, '');
        if (str.startsWith('MEGA{')) {
            try {
                const jsonStr = str.slice(4);
                const endIdx = jsonStr.lastIndexOf('}');
                if (endIdx >= 0) return JSON.parse(jsonStr.slice(0, endIdx + 1));
            } catch { /* corrupted attrs */ }
        }
        return null;
    }
    static xor16(block, prev) {
        const mixed = new Uint8Array(16);
        for (let i = 0; i < 16; i++) mixed[i] = block[i] ^ prev[i];
        return mixed;
    }
    static uploadMac(plainBytes, keyA32) {
        const keyBytes = this.a32ToStr(keyA32.slice(0, 4));
        const aes = new AES_ECB(keyBytes);
        const ivBytes = this.a32ToStr([keyA32[4], keyA32[5], keyA32[4], keyA32[5]]);
        let cbcPrev = ivBytes;
        const blockCount = Math.max(1, Math.ceil(plainBytes.length / 16));
        for (let i = 0; i < blockCount; i++) {
            const block = new Uint8Array(16);
            const start = i * 16;
            block.set(plainBytes.slice(start, Math.min(start + 16, plainBytes.length)));
            cbcPrev = aes.encrypt(this.xor16(block, cbcPrev));
        }
        const mac = aes.encrypt(cbcPrev);
        const macA32 = this.strToA32(mac);
        return [(macA32[0] ^ macA32[1]) >>> 0, (macA32[2] ^ macA32[3]) >>> 0];
    }
    static async aesCtrCrypt(data, keyA32) {
        const keyBytes = this.a32ToStr(keyA32.slice(0, 4));
        const counter = new Uint8Array(16);
        const ivBytes = this.a32ToStr([keyA32[4], keyA32[5]]);
        counter.set(ivBytes, 0);
        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['encrypt', 'decrypt']);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-CTR', counter, length: 64 }, cryptoKey, data);
        return new Uint8Array(encrypted);
    }

    // ===================== v1 legacy key derivation =====================
    /**
     * Derives the password AES key for MEGA v1 (pre-salt) accounts.
     * Mirrors mega.py `prepare_key`:  65 536 rounds of AES-ECB over a
     * well-known initial key, using 4-word chunks of the password as the
     * per-round cipher key.
     *
     * @param  {string} password  Plaintext password
     * @return {number[]}         4-element a32 AES key
     */
    static prepareKey(password) {
        const parray = this.strToA32(new TextEncoder().encode(password));
        let pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56];
        for (let r = 0; r < 65536; r++) {
            for (let j = 0; j < parray.length; j += 4) {
                const k = [0, 0, 0, 0];
                for (let i = 0; i < 4; i++) {
                    if (j + i < parray.length) k[i] = parray[j + i];
                }
                const keyBytes  = this.a32ToStr(k);
                const dataBytes = this.a32ToStr(pkey);
                const aes       = new AES_ECB(keyBytes);
                pkey = this.strToA32(aes.encrypt(dataBytes));
            }
        }
        return pkey;
    }

    /**
     * Produces the legacy "uh" user-hash sent with `us` login requests.
     * Mirrors mega.py `stringhash`:  XOR-fold the email into 4 words,
     * then 16 384 rounds of AES-ECB encrypt with the password key.
     *
     * @param  {string}   email   Lowercased e-mail
     * @param  {number[]} aesKey  4-element a32 password key (from prepareKey)
     * @return {string}           Base64url-encoded hash (first 8 bytes)
     */
    static stringHash(email, aesKey) {
        const s32 = this.strToA32(new TextEncoder().encode(email));
        let h32 = [0, 0, 0, 0];
        for (let i = 0; i < s32.length; i++) {
            h32[i % 4] = (h32[i % 4] ^ s32[i]) >>> 0;
        }
        const keyBytes = this.a32ToStr(aesKey);
        const aes = new AES_ECB(keyBytes);
        for (let r = 0; r < 16384; r++) {
            h32 = this.strToA32(aes.encrypt(this.a32ToStr(h32)));
        }
        return this.a32ToBase64([h32[0], h32[2]]);
    }
}

// ===================== MEGA DRIVE CLASS =====================

class MegaDrive {
    constructor(config, order, rootOverride = null, accountOverride = null) {
        this.order = order;
        this.root    = rootOverride || megaConfig.roots?.[order] || {
            id: `account-${order}`,
            name: accountOverride?.email || megaConfig.accounts?.[order]?.email || `MEGA Account ${order + 1}`,
            public: true
        };
        this.account = accountOverride || megaConfig.accounts?.[order] || megaConfig.accounts?.[0] || null;
        this.url_path_prefix = '/mega' + order + ':';
        this.sid       = null;
        this.masterKey = null;
        this.sequenceNum = Math.floor(Math.random() * 0xFFFFFFFF);
        this.nodes       = new Map();
        this.rootNodeId  = null;
        this.folderKey   = null;
        this.folderHandle = null;
        this.isPublicFolder = false;
        // O(1) lookup indexes
        this.childrenIndex = new Map();   // parentId → Set<nodeId>
        this.nameIndex     = new Map();   // "parentId\0name" → [nodeId, …]
        this.hlsProbeCache = new Map();
        // A player normally makes several range requests (metadata, moov atom,
        // then media). Reusing MEGA's temporary URL avoids an API round trip for
        // every one of those requests.
        this.downloadUrlCache = new Map();
        this.initialized = false;
    }

    _indexNode(nodeId, parentId, name) {
        if (!this.childrenIndex.has(parentId)) {
            this.childrenIndex.set(parentId, new Set());
        }
        this.childrenIndex.get(parentId).add(nodeId);
        const nk = parentId + '\0' + name;
        if (!this.nameIndex.has(nk)) {
            this.nameIndex.set(nk, []);
        }
        this.nameIndex.get(nk).push(nodeId);
    }

    /**
     * Walk a path using the nameIndex.
     * Returns the parentId of the deepest folder reached.
     * Sets `valid` to false if any segment was not found.
     */
    _walkPath(parts) {
        let parentId = this.rootNodeId;
        let valid = true;
        for (const part of parts) {
            const nk = parentId + '\0' + part;
            const candidates = this.nameIndex.get(nk);
            let found = false;
            if (candidates) {
                for (const cid of candidates) {
                    const n = this.nodes.get(cid);
                    if (n && (n.type === 1 || n.type === 2)) {
                        parentId = cid;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) { valid = false; break; }
        }
        return { parentId, valid };
    }

    // ---------- link parsing ----------
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

    // ---------- API ----------
    async _sleep(n) {
        const delay = Math.min(1000 * 2 ** n, 20000);
        return new Promise(r => setTimeout(r, delay));
    }

    async apiRequest(data, params = '', retries = 5) {
        let finalParams = params;
        if (this.sid) finalParams += '&sid=' + this.sid;
        
        const finalUrl = MEGA_API_URL + '?id=' + (this.sequenceNum++);
        const url = finalUrl + finalParams;

        let hashcashHeader = null;
        for (let attempt = 0; attempt <= retries; attempt++) {
            const headers = { 'Content-Type': 'application/json' };
            if (hashcashHeader) {
                headers['X-Hashcash'] = hashcashHeader;
            }
            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(Array.isArray(data) ? data : [data])
                });
                
                if (res.status === 402) {
                    const challenge = res.headers.get('X-Hashcash');
                    if (!challenge) {
                        await this._sleep(attempt);
                        continue;
                    }
                    const parts = challenge.split(':');
                    if (parts.length !== 4 || parts[0] !== '1') {
                        await this._sleep(attempt);
                        continue;
                    }
                    const easiness = parseInt(parts[1], 10);
                    const token = parts[3];
                    const result = await this._solveHashcash(token, easiness);
                    hashcashHeader = `1:${token}:${result}`;
                    continue;
                }

                if (!res.ok) { await this._sleep(attempt); continue; }
                const json = await res.json();
                if (json === -3 || json?.[0] === -3) { await this._sleep(attempt); continue; }
                return json;
            } catch (e) {
                await this._sleep(attempt);
            }
        }
        console.error('Mega API: all retries exhausted for', JSON.stringify(data).slice(0, 80));
        return null;
    }

    async _solveHashcash(tokenBase64Url, easiness) {
        const tokenBytes = MegaCrypto.base64UrlDecode(tokenBase64Url);
        if (tokenBytes.length !== 48) {
            throw new Error("Token size must be 48 bytes");
        }

        const e1 = ((easiness & 63) << 1) + 1;
        const e2 = ((easiness >> 6) * 7) + 3;
        const threshold = (e1 << e2) >>> 0;

        const bufSize = 4 + 262144 * 48;
        const buf = new Uint8Array(bufSize);
        for (let i = 0; i < 262144; i++) {
            buf.set(tokenBytes, 4 + i * 48);
        }

        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        let counter = 0;

        while (true) {
            counter++;
            view.setUint32(0, counter, true);

            const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
            const hashView = new DataView(hashBuffer);
            const hashVal = hashView.getUint32(0, false);

            if (hashVal <= threshold) {
                const resultBytes = new Uint8Array(4);
                const resultView = new DataView(resultBytes.buffer);
                resultView.setUint32(0, counter, true);
                return MegaCrypto.base64UrlEncode(resultBytes);
            }
        }
    }

    // ---------- login ----------
    async login(email, password) {
        try {
            const saltResp = await this.apiRequest({ a: 'us0', user: email.toLowerCase() });
            let passwordAes, userHash;
            if (saltResp?.[0]?.s) {
                // ---- v2 account (PBKDF2) ----
                const userSalt  = MegaCrypto.base64ToA32(saltResp[0].s);
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
                userHash    = MegaCrypto.base64UrlEncode(pbkdf2Key.slice(16, 32));
            } else {
                // ---- v1 account (legacy key derivation) ----
                passwordAes = MegaCrypto.prepareKey(password);
                userHash    = MegaCrypto.stringHash(email.toLowerCase(), passwordAes);
            }
            const loginResp = await this.apiRequest({
                a: 'us', user: email.toLowerCase(), uh: userHash
            });
            if (!loginResp?.[0] || typeof loginResp[0] === 'number') {
                console.error('Mega: Login failed', loginResp);
                return false;
            }
            const resp = loginResp[0];
            const encryptedMasterKey = MegaCrypto.base64ToA32(resp.k);
            this.masterKey = MegaCrypto.decryptKey(encryptedMasterKey, passwordAes);
            if (resp.tsid) {
                this.sid = resp.tsid;
            } else if (resp.csid) {
                try {
                    const mkBytes = MegaCrypto.a32ToStr(this.masterKey);
                    const pkBytes = MegaCrypto.base64UrlDecode(resp.privk);
                    const decryptedPk = MegaCrypto.aesEcbDecrypt(pkBytes, mkBytes);
                    const csidBytes = MegaCrypto.base64UrlDecode(resp.csid);

                    const getMPI = (bytes, offset = 0) => {
                        const bits = (bytes[offset] << 8) | bytes[offset + 1];
                        const len = (bits + 7) >> 3;
                        const slice = bytes.slice(offset + 2, offset + 2 + len);
                        let hex = '';
                        for (let i = 0; i < slice.length; i++) {
                            hex += slice[i].toString(16).padStart(2, '0');
                        }
                        const val = hex ? BigInt('0x' + hex) : 0n;
                        return { val, nextOffset: offset + 2 + len };
                    };

                    const getRSAKey = (bytes) => {
                        const pRes = getMPI(bytes, 0);
                        const qRes = getMPI(bytes, pRes.nextOffset);
                        const dRes = getMPI(bytes, qRes.nextOffset);
                        return { p: pRes.val, q: qRes.val, d: dRes.val };
                    };

                    const modPow = (base, exponent, modulus) => {
                        if (modulus === 1n) return 0n;
                        let result = 1n;
                        base = base % modulus;
                        while (exponent > 0n) {
                            if (exponent % 2n === 1n) {
                                result = (result * base) % modulus;
                            }
                            exponent = exponent / 2n;
                            base = (base * base) % modulus;
                        }
                        return result;
                    };

                    const decryptRSA = (m, p, q, d) => {
                        const n = p * q;
                        const r = modPow(m, d, n);
                        let hex = r.toString(16);
                        if (hex.length % 2 !== 0) hex = '0' + hex;
                        const len = hex.length / 2;
                        const bytes = new Uint8Array(len);
                        for (let i = 0; i < len; i++) {
                            bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                        }
                        return bytes;
                    };

                    const mRes = getMPI(csidBytes, 0);
                    const { p, q, d } = getRSAKey(decryptedPk);
                    const r = decryptRSA(mRes.val, p, q, d);

                    this.sid = MegaCrypto.base64UrlEncode(r.slice(0, 43));
                } catch (e) {
                    console.error('Mega: Failed to decrypt csid session ID:', e);
                    this.sid = resp.csid;
                }
            }
            return !!this.sid;
        } catch (e) {
            console.error('Mega: Login error:', e);
            return false;
        }
    }

    // ---------- init ----------
    async init() {
        if (this.initialized) return;
        try {
            const parsed = this.root?.link ? this.parseFolderLink(this.root.link) : null;
            if (parsed?.needsLogin || !parsed) {
                if (this.account?.email && this.account?.password) {
                    const loggedIn = await this.login(this.account.email, this.account.password);
                    if (loggedIn) await this.loadAccountFiles(parsed?.fmPath);
                }
            } else if (parsed?.handle && parsed?.key) {
                this.isPublicFolder = true;
                this.folderHandle   = parsed.handle;
                this.folderKey      = MegaCrypto.base64ToA32(parsed.key);
                await this.loadPublicFolder();
            }
        } catch (e) {
            console.error('Mega: Init error:', e);
        }
        this.initialized = true;
    }

    // ---------- load files ----------
    async loadAccountFiles(fmPath = null) {
        const resp = await this.apiRequest([{ a: 'f', c: 1 }]);
        if (!resp?.[0]?.f) return;
        // Pass 1: find root node (t===2) before processing children
        for (const file of resp[0].f) {
            if (file.t === 2 && !this.rootNodeId) {
                this.rootNodeId = file.h;
            }
        }
        // Pass 2: process all nodes (rootNodeId is now set)
        for (const file of resp[0].f) {
            await this.processNode(file, false);
        }
        if (fmPath && this.nodes.has(fmPath)) {
            this.rootNodeId = fmPath;
        }
    }

    async loadPublicFolder() {
        const resp = await this.apiRequest(
            [{ a: 'f', c: 1, r: 1, ca: 1 }],
            '&n=' + this.folderHandle
        );
        if (!resp?.[0] || typeof resp[0] === 'number') {
            const errors = {
                '-2': 'Invalid arguments', '-9': 'Object not found',
                '-11': 'Access denied', '-14': 'Invalid key',
                '-16': 'Blocked', '-17': 'Over quota'
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
                if (node.type === 1) { this.rootNodeId = id; break; }
            }
        }
    }

    // ---------- node processing ----------
    async processNode(node, isPublic) {
        let name = null;
        let key  = null;
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
                    const keyParts   = node.k.split(':');
                    const encKeyB64  = keyParts[keyParts.length - 1];
                    const encKeyBytes = MegaCrypto.base64UrlDecode(encKeyB64);
                    const encKey     = MegaCrypto.strToA32(encKeyBytes);
                    const decKey     = MegaCrypto.decryptKey(encKey, this.folderKey);
                    key = decKey;
                    const aesKey = (node.t === 0 && decKey.length >= 8)
                        ? [(decKey[0]^decKey[4])>>>0, (decKey[1]^decKey[5])>>>0,
                           (decKey[2]^decKey[6])>>>0, (decKey[3]^decKey[7])>>>0]
                        : decKey.slice(0, 4);
                    const attrs = MegaCrypto.decryptAttr(MegaCrypto.base64UrlDecode(node.a), aesKey);
                    if (attrs?.n) name = attrs.n;
                } else if (this.masterKey) {
                    const keyParts = node.k.split('/');
                    for (const part of keyParts) {
                        if (!part.includes(':')) continue;
                        const [, encKeyB64] = part.split(':');
                        try {
                            const encKey = MegaCrypto.base64ToA32(encKeyB64);
                            const decKey = MegaCrypto.decryptKey(encKey, this.masterKey);
                            key = decKey;
                            const aesKey = (node.t === 0 && decKey.length >= 8)
                                ? [(decKey[0]^decKey[4])>>>0, (decKey[1]^decKey[5])>>>0,
                                   (decKey[2]^decKey[6])>>>0, (decKey[3]^decKey[7])>>>0]
                                : decKey.slice(0, 4);
                            const attrs = MegaCrypto.decryptAttr(
                                MegaCrypto.base64UrlDecode(node.a), aesKey);
                            if (attrs?.n) { name = attrs.n; break; }
                        } catch { /* try next key share */ }
                    }
                }
            } catch (e) {
                console.error('Mega: Error decrypting node', node.h, e.message);
            }
        }
        if (!name) name = 'Item_' + node.h;
        const parentId = node.p || this.rootNodeId;
        const nodeInfo = {
            id:   node.h,
            name,
            parentId,
            type: node.t,
            size: node.s ?? 0,
            key,
            mimeType: (node.t === 1 || node.t === 2)
                ? 'application/vnd.google-apps.folder'
                : this.getMimeType(name),
            modifiedTime: node.ts
                ? new Date(node.ts * 1000).toISOString()
                : new Date().toISOString()
        };
        this.nodes.set(node.h, nodeInfo);
        this._indexNode(node.h, parentId, name);
    }

    // ---------- mime ----------
    getMimeType(name) {
        const ext = (name || '').split('.').pop().toLowerCase();
        const types = {
            mp4:'video/mp4', mkv:'video/x-matroska', avi:'video/x-msvideo',
            webm:'video/webm', mov:'video/quicktime', m4v:'video/x-m4v',
            ts:'video/mp2t', m2ts:'video/mp2t', mts:'video/mp2t',
            mp3:'audio/mpeg', flac:'audio/flac', wav:'audio/wav',
            m4a:'audio/mp4', aac:'audio/aac', ogg:'audio/ogg',
            jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png',
            gif:'image/gif', webp:'image/webp', svg:'image/svg+xml',
            pdf:'application/pdf', zip:'application/zip',
            rar:'application/x-rar-compressed', '7z':'application/x-7z-compressed',
            txt:'text/plain', html:'text/html', css:'text/css',
            js:'application/javascript', json:'application/json',
            srt:'application/x-subrip', vtt:'text/vtt', ass:'text/x-ass'
        };
        return types[ext] || 'application/octet-stream';
    }

    // ---------- auth ----------
    basicAuthResponse(request) {
        if (!this.root?.auth || Object.keys(this.root.auth).length === 0) return null;
        const auth   = this.root.auth;
        const header = request.headers.get('Authorization');
        if (header) {
            try {
                const [user, pass] = atob(header.split(' ').pop()).split(':');
                if (auth[user] === pass) return null;
            } catch { /* bad header */ }
        }
        return new Response('Unauthorized', {
            headers: { 'WWW-Authenticate': 'Basic realm="Mega"', 'content-type': 'text/html' },
            status: 401
        });
    }

    ensureWritableAccount() {
        if (this.isPublicFolder || !this.masterKey || !this.sid) {
            throw new Error('This MEGA root is not a writable logged-in account root.');
        }
    }

    // Returns the account quota in bytes.  This deliberately uses the logged-in
    // account API rather than folder sizes, so the dashboard can show the real
    // amount still available before choosing an upload target.
    async getStorageInfo() {
        if (!this.initialized) await this.init();
        this.ensureWritableAccount();
        const response = await this.apiRequest({ a: 'uq', xfer: 0 });
        const quota = Array.isArray(response) ? response[0] : response;
        if (!quota || typeof quota === 'number') {
            throw new Error('MEGA storage information is unavailable.');
        }
        const total = Number(quota.mstrg ?? quota.max ?? 0);
        const used = Number(quota.cstrg ?? quota.used ?? 0);
        return {
            total: Number.isFinite(total) ? total : 0,
            used: Number.isFinite(used) ? used : 0,
            free: Math.max(0, total - used)
        };
    }

    async getDownloadInfo(fileId) {
        const now = Date.now();
        const cached = this.downloadUrlCache.get(fileId);
        if (cached && cached.expiresAt > now) return cached.promise;

        const entry = { expiresAt: now + 15 * 60 * 1000, promise: null };
        entry.promise = (async () => {
            const params = this.isPublicFolder ? '&n=' + this.folderHandle : '';
            const response = await this.apiRequest([{ a: 'g', g: 1, n: fileId }], params);
            const info = response?.[0];
            if (!info?.g) throw new Error('MEGA did not return a download URL.');
            return { url: info.g, size: Number(info.s || 0) };
        })();
        this.downloadUrlCache.set(fileId, entry);
        try {
            return await entry.promise;
        } catch (error) {
            this.downloadUrlCache.delete(fileId);
            throw error;
        }
    }

    invalidateDownloadInfo(fileId) {
        this.downloadUrlCache.delete(fileId);
    }

    folderIdFromPath(path = '/') {
        const parts = path.split('/').filter(Boolean);
        const { parentId, valid } = this._walkPath(parts);
        if (!valid) throw new Error('Target folder path was not found.');
        const node = this.nodes.get(parentId);
        if (node && node.mimeType !== 'application/vnd.google-apps.folder') {
            throw new Error('Target path is not a folder.');
        }
        return parentId;
    }

    addLocalNode(id, parentId, name, type, size = 0, key = null) {
        const nodeInfo = {
            id,
            name,
            parentId,
            type,
            size,
            key,
            mimeType: type === 1 ? 'application/vnd.google-apps.folder' : this.getMimeType(name),
            modifiedTime: new Date().toISOString()
        };
        this.nodes.set(id, nodeInfo);
        this._indexNode(id, parentId, name);
        return nodeInfo;
    }

    // ===================== create folder =====================
    async createFolder(parentPath = '/', folderName = '') {
        if (!this.initialized) await this.init();
        this.ensureWritableAccount();
        const cleanName = String(folderName || '').trim().replace(/\//g, '');
        if (!cleanName) throw new Error('Folder name is required.');
        const parentId = this.folderIdFromPath(parentPath);
        const folderKey = MegaCrypto.randomA32(4);
        const encryptedAttrs = MegaCrypto.base64UrlEncode(MegaCrypto.encryptAttr({ n: cleanName }, folderKey));
        const encryptedKey = MegaCrypto.a32ToBase64(MegaCrypto.encryptKey(folderKey, this.masterKey));
        const resp = await this.apiRequest({
            a: 'p',
            t: parentId,
            n: [{
                h: 'xxxxxxxx',
                t: 1,
                a: encryptedAttrs,
                k: encryptedKey
            }]
        });
        if (!resp?.[0]?.f?.[0]?.h) {
            throw new Error('MEGA folder create failed.');
        }
        const id = resp[0].f[0].h;
        this.addLocalNode(id, parentId, cleanName, 1, 0, folderKey);
        return { id, path: `${parentPath.replace(/\/$/, '')}/${cleanName}`.replace(/^$/, '/') };
    }

    // ===================== upload (chunked, low-memory) =====================
    static CHUNK_SIZE = 8 * 1024 * 1024; // 8 MB default

    async uploadFile(file, uploadPath = '/') {
        if (!this.initialized) await this.init();
        this.ensureWritableAccount();
        if (!file || typeof file.arrayBuffer !== 'function') {
            throw new Error('A file is required.');
        }
        const parentId = this.folderIdFromPath(uploadPath);
        const fileName = file.name || 'upload.bin';
        const fileSize = file.size || 0;

        // Request upload URL from MEGA
        const uploadUrlResp = await this.apiRequest({ a: 'u', s: fileSize });
        const uploadUrl = uploadUrlResp?.[0]?.p || uploadUrlResp?.p;
        if (!uploadUrl) throw new Error('MEGA upload URL request failed.');

        const uploadKey = MegaCrypto.randomA32(6);
        const CHUNK = MegaDrive.CHUNK_SIZE;

        // Prepare AES-CTR key
        const aesKeyBytes = MegaCrypto.a32ToStr(uploadKey.slice(0, 4));
        const cryptoKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-CTR' }, false, ['encrypt']);
        const baseNonce = MegaCrypto.a32ToStr([uploadKey[4], uploadKey[5]]);

        // MAC state
        const macKeyBytes = MegaCrypto.a32ToStr(uploadKey.slice(0, 4));
        const macAes = new AES_ECB(macKeyBytes);
        const ivBytes = MegaCrypto.a32ToStr([uploadKey[4], uploadKey[5], uploadKey[4], uploadKey[5]]);
        let macPrev = ivBytes;

        // Upload in chunks
        let offset = 0;
        let completionHandle = null;
        let chunkIdx = 0;
        const totalChunks = Math.max(1, Math.ceil(fileSize / CHUNK));

        while (offset < fileSize) {
            const chunkEnd = Math.min(offset + CHUNK, fileSize);
            const chunkBlob = file.slice(offset, chunkEnd);
            const plainBytes = new Uint8Array(await chunkBlob.arrayBuffer());

            // Update MAC for this chunk
            const blockCount = Math.max(1, Math.ceil(plainBytes.length / 16));
            for (let i = 0; i < blockCount; i++) {
                const block = new Uint8Array(16);
                const start = i * 16;
                block.set(plainBytes.slice(start, Math.min(start + 16, plainBytes.length)));
                macPrev = macAes.encrypt(MegaCrypto.xor16(block, macPrev));
            }

            // AES-CTR encrypt
            const blockNum = Math.floor(offset / 16);
            const counter = new Uint8Array(16);
            counter.set(new Uint8Array(baseNonce), 0);
            const high = Math.floor(blockNum / 0x100000000);
            const low = blockNum >>> 0;
            counter[8]  = (high >>> 24) & 0xff;
            counter[9]  = (high >>> 16) & 0xff;
            counter[10] = (high >>> 8)  & 0xff;
            counter[11] =  high         & 0xff;
            counter[12] = (low >>> 24)  & 0xff;
            counter[13] = (low >>> 16)  & 0xff;
            counter[14] = (low >>> 8)   & 0xff;
            counter[15] =  low          & 0xff;

            const encBuf = await crypto.subtle.encrypt(
                { name: 'AES-CTR', counter, length: 64 }, cryptoKey, plainBytes
            );
            const encryptedBytes = new Uint8Array(encBuf);

            // Upload chunk with retries
            let uploadOk = false;
            for (let retry = 0; retry <= 3; retry++) {
                try {
                    const uploadResp = await fetch(`${uploadUrl}/${offset}`, {
                        method: 'POST',
                        body: encryptedBytes
                    });
                    if (!uploadResp.ok) {
                        if (retry < 3) { await this._sleep(retry); continue; }
                        throw new Error(`MEGA chunk upload failed with HTTP ${uploadResp.status}.`);
                    }
                    const respText = (await uploadResp.text()).trim();
                    // Last chunk returns the completion handle (a string, not a number)
                    if (chunkIdx === totalChunks - 1 || (respText && respText.length > 5 && !/^-?\d+$/.test(respText))) {
                        completionHandle = respText;
                    }
                    uploadOk = true;
                    break;
                } catch (e) {
                    if (retry < 3) { await this._sleep(retry); continue; }
                    throw e;
                }
            }
            if (!uploadOk) throw new Error('MEGA chunk upload failed after retries.');

            offset = chunkEnd;
            chunkIdx++;
        }

        if (!completionHandle || /^-?\d+$/.test(completionHandle)) {
            throw new Error('MEGA upload did not return a valid completion handle.');
        }

        // Compute final MAC
        const finalMac = macAes.encrypt(macPrev);
        const macA32 = MegaCrypto.strToA32(finalMac);
        const metaMac = [(macA32[0] ^ macA32[1]) >>> 0, (macA32[2] ^ macA32[3]) >>> 0];

        // Commit file
        const attrKey = uploadKey.slice(0, 4);
        const encryptedAttrs = MegaCrypto.base64UrlEncode(MegaCrypto.encryptAttr({ n: fileName }, attrKey));
        const fileKey = [
            (uploadKey[0] ^ uploadKey[4]) >>> 0,
            (uploadKey[1] ^ uploadKey[5]) >>> 0,
            (uploadKey[2] ^ metaMac[0]) >>> 0,
            (uploadKey[3] ^ metaMac[1]) >>> 0,
            uploadKey[4],
            uploadKey[5],
            metaMac[0],
            metaMac[1]
        ];
        const encryptedKey = MegaCrypto.a32ToBase64(MegaCrypto.encryptKey(fileKey, this.masterKey));
        const resp = await this.apiRequest({
            a: 'p',
            t: parentId,
            n: [{
                h: completionHandle,
                t: 0,
                a: encryptedAttrs,
                k: encryptedKey
            }]
        });
        if (!resp?.[0]?.f?.[0]?.h) {
            throw new Error('MEGA upload commit failed.');
        }
        const id = resp[0].f[0].h;
        this.addLocalNode(id, parentId, fileName, 0, fileSize, fileKey);
        return { id, name: fileName, size: fileSize, path: `${uploadPath.replace(/\/$/, '')}/${fileName}`.replace(/^$/, '/') };
    }

    // ===================== folder tree =====================
    async listFolders(basePath = '/') {
        if (!this.initialized) await this.init();
        const parts = basePath.split('/').filter(p => p);
        const { parentId, valid } = this._walkPath(parts);
        if (!valid) return [];
        return this._buildFolderTree(parentId, basePath);
    }

    _buildFolderTree(parentId, currentPath = '/') {
        const childIds = this.childrenIndex.get(parentId) || new Set();
        const folders = [];
        for (const id of childIds) {
            const node = this.nodes.get(id);
            if (!node || node.type !== 1) continue;
            const folderPath = `${currentPath.replace(/\/$/, '')}/${node.name}/`;
            folders.push({
                id: node.id,
                name: node.name,
                path: folderPath,
                children: this._buildFolderTree(id, folderPath)
            });
        }
        folders.sort((a, b) => a.name.localeCompare(b.name));
        return folders;
    }

    // ===================== ensure nested folder path =====================
    async ensureFolder(folderPath = '/') {
        if (!this.initialized) await this.init();
        this.ensureWritableAccount();
        const parts = folderPath.split('/').filter(p => p);
        if (!parts.length) return this.rootNodeId;

        let currentParentId = this.rootNodeId;
        let currentBasePath = '/';
        for (const part of parts) {
            const nk = currentParentId + '\0' + part;
            const candidates = this.nameIndex.get(nk);
            let found = false;
            if (candidates) {
                for (const cid of candidates) {
                    const n = this.nodes.get(cid);
                    if (n && (n.type === 1 || n.type === 2)) {
                        currentParentId = cid;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                // Create the missing folder
                const result = await this.createFolder(currentBasePath, part);
                currentParentId = result.id;
            }
            currentBasePath = `${currentBasePath.replace(/\/$/, '')}/${part}/`;
        }
        return currentParentId;
    }

    // ===================== list =====================
    async list(path = '/', pageToken = null, pageIndex = 0) {
        if (!this.initialized) await this.init();
        const parts = path.split('/').filter(p => p);
        const { parentId, valid } = this._walkPath(parts);
        if (!valid) {
            return { nextPageToken: null, curPageIndex: pageIndex, data: { files: [] } };
        }
        const childIds = this.childrenIndex.get(parentId) || new Set();
        const files = [];
        for (const id of childIds) {
            if (id === this.rootNodeId) continue;
            const node = this.nodes.get(id);
            if (!node || node.type === 2) continue;
            files.push({
                id:   node.id,
                name: node.name,
                mimeType: node.mimeType,
                size: String(node.size),
                modifiedTime: node.modifiedTime
            });
        }
        files.sort((a, b) => {
            const af = a.mimeType === 'application/vnd.google-apps.folder';
            const bf = b.mimeType === 'application/vnd.google-apps.folder';
            if (af && !bf) return -1;
            if (!af && bf) return 1;
            return a.name.localeCompare(b.name);
        });
        return { nextPageToken: null, curPageIndex: pageIndex, data: { files } };
    }

    // ===================== file =====================
    async file(path) {
        if (!this.initialized) await this.init();
        const parts = path.split('/').filter(p => p);
        if (!parts.length) return null;
        let parentId = this.rootNodeId;
        for (let i = 0; i < parts.length; i++) {
            const part   = parts[i];
            const isLast = i === parts.length - 1;
            const nk = parentId + '\0' + part;
            const candidates = this.nameIndex.get(nk);
            if (!candidates || candidates.length === 0) return null;
            if (isLast) {
                return this.nodes.get(candidates[0]) || null;
            }
            // Intermediate segment — must be a folder
            let found = false;
            for (const cid of candidates) {
                const n = this.nodes.get(cid);
                if (n && (n.type === 1 || n.type === 2)) {
                    parentId = cid;
                    found = true;
                    break;
                }
            }
            if (!found) return null;
        }
        return null;
    }

    // ===================== down =====================
    async down(fileId, range = '', inline = false, method = 'GET', ts = false, hlsStart = -1, hlsEnd = -1, forceDownload = false) {
        if (!this.initialized) await this.init();
        // ---- CORS preflight ----
        if (method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
                    'Access-Control-Allow-Headers': 'Range',
                    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges',
                    'Access-Control-Max-Age': '86400'
                }
            });
        }
        const node = this.nodes.get(fileId);
        if (!node) {
            return new Response(not_found, {
                status: 404, headers: { 'content-type': 'text/html' }
            });
        }
        // .ts → .mkv rename for player compat
        let fileName = node.name;
        let mimeType = node.mimeType;
        if (/\.(ts|m2ts|mts)$/i.test(fileName)) {
            fileName = fileName.replace(/\.(ts|m2ts|mts)$/i, '.mkv');
            mimeType = 'video/x-matroska';
        }
        if (ts) mimeType = 'video/mp2t';
        try {
            const downloadInfo = await this.getDownloadInfo(fileId);
            const downloadUrl = downloadInfo.url;
            const fileSize = downloadInfo.size || node.size || 0;
            // ---- Parse client range ----
            let startByte = 0;
            let endByte   = fileSize - 1;
            let clientRequestedRange = false;
            if (hlsStart >= 0 && hlsEnd >= 0) {
                startByte = hlsStart;
                endByte   = Math.min(hlsEnd, fileSize - 1);
                clientRequestedRange = true;
            } else if (range && range.startsWith('bytes=')) {
                const rangeParts = range.replace('bytes=', '').split('-');
                if (rangeParts[0] === '') {
                    // Suffix range: bytes=-500 = last 500 bytes
                    const suffix = parseInt(rangeParts[1]) || 0;
                    startByte = Math.max(0, fileSize - suffix);
                    endByte = fileSize - 1;
                } else {
                    startByte = parseInt(rangeParts[0]) || 0;
                    endByte   = rangeParts[1] ? parseInt(rangeParts[1]) : fileSize - 1;
                }
                clientRequestedRange = true;
            }
            if (startByte < 0 || startByte >= fileSize || endByte < startByte) {
                return new Response(null, {
                    status: 416,
                    headers: { 'Content-Range': `bytes */${fileSize}`, 'Accept-Ranges': 'bytes' }
                });
            }
            if (endByte >= fileSize) endByte = fileSize - 1;
            const contentLength = endByte - startByte + 1;
            // ---- Shared CORS headers ----
            const corsHeaders = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
                'Access-Control-Allow-Headers': 'Range',
                'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges'
            };
            const isMedia     = mimeType.startsWith('video/') || mimeType.startsWith('audio/');
            const disposition = forceDownload ? 'attachment' : ((inline || isMedia) ? 'inline' : 'attachment');
            // ---- Build response headers ----
            const respHeaders = {
                'Content-Type': mimeType,
                'Content-Disposition': `${disposition}; filename*=UTF-8''${encodeURIComponent(fileName)}`,
                'Accept-Ranges': 'bytes',
                'Content-Length': String(contentLength),
                ...corsHeaders
            };
            if (clientRequestedRange) {
                respHeaders['Content-Range'] = `bytes ${startByte}-${endByte}/${fileSize}`;
            }
            const statusCode = clientRequestedRange ? 206 : 200;
            // ---- HEAD — return metadata only, no fetch ----
            if (method === 'HEAD') {
                return new Response(null, { status: statusCode, headers: respHeaders });
            }
            const fileKey = node.key;
            // Build AES-CTR counter helper (hoisted, used in both paths)
            const buildCounter = (baseNonce, blockNum) => {
                const ctr = new Uint8Array(16);
                ctr.set(baseNonce, 0);
                const high = Math.floor(blockNum / 0x100000000);
                const low  = blockNum >>> 0;
                ctr[8]  = (high >>> 24) & 0xff;
                ctr[9]  = (high >>> 16) & 0xff;
                ctr[10] = (high >>> 8)  & 0xff;
                ctr[11] =  high         & 0xff;
                ctr[12] = (low >>> 24)  & 0xff;
                ctr[13] = (low >>> 16)  & 0xff;
                ctr[14] = (low >>> 8)   & 0xff;
                ctr[15] =  low          & 0xff;
                return ctr;
            };
            // ============ Unencrypted path (no valid key) ============
            if (!fileKey || fileKey.length < 8) {
                const fetchHeaders = clientRequestedRange ? { 'Range': `bytes=${startByte}-${endByte}` } : {};
                const fileResp = await fetch(downloadUrl, { headers: fetchHeaders });
                if (!fileResp.ok && fileResp.status !== 206) {
                    console.error('Mega: Fetch failed', fileResp.status);
                    return new Response('Fetch failed', { status: 502 });
                }
                // Upstream ignored Range — send full body, drop range headers
                if (fileResp.status === 200 && clientRequestedRange) {
                    delete respHeaders['Content-Range'];
                    respHeaders['Content-Length'] = String(fileSize);
                    return new Response(fileResp.body, { status: 200, headers: respHeaders });
                }
                return new Response(fileResp.body, { status: statusCode, headers: respHeaders });
            }
            // ============ Encrypted path ============
            const aesKey = [
                (fileKey[0] ^ fileKey[4]) >>> 0,
                (fileKey[1] ^ fileKey[5]) >>> 0,
                (fileKey[2] ^ fileKey[6]) >>> 0,
                (fileKey[3] ^ fileKey[7]) >>> 0
            ];
            const keyBytes = new Uint8Array(16);
            for (let i = 0; i < 4; i++) {
                keyBytes[i*4]   = (aesKey[i] >>> 24) & 0xff;
                keyBytes[i*4+1] = (aesKey[i] >>> 16) & 0xff;
                keyBytes[i*4+2] = (aesKey[i] >>> 8)  & 0xff;
                keyBytes[i*4+3] =  aesKey[i]         & 0xff;
            }
            const baseNonce = new Uint8Array(8);
            baseNonce[0] = (fileKey[4] >>> 24) & 0xff;
            baseNonce[1] = (fileKey[4] >>> 16) & 0xff;
            baseNonce[2] = (fileKey[4] >>> 8)  & 0xff;
            baseNonce[3] =  fileKey[4]         & 0xff;
            baseNonce[4] = (fileKey[5] >>> 24) & 0xff;
            baseNonce[5] = (fileKey[5] >>> 16) & 0xff;
            baseNonce[6] = (fileKey[5] >>> 8)  & 0xff;
            baseNonce[7] =  fileKey[5]         & 0xff;
            // Align fetch to 16-byte AES blocks
            const blockStart    = Math.floor(startByte / 16) * 16;
            const blockOffset   = startByte - blockStart;
            const startBlockNum = Math.floor(blockStart / 16);
            // Internal Range fetch (avoids MEGA 509)
            const fileResp = await fetch(downloadUrl, {
                headers: { 'Range': `bytes=${blockStart}-${endByte}` }
            });
            if (!fileResp.ok && fileResp.status !== 206) {
                console.error('Mega: Fetch failed', fileResp.status);
                return new Response('Fetch failed', { status: 502 });
            }
            // Upstream ignored Range — decrypt from block 0, skip to startByte
            if (fileResp.status === 200 && clientRequestedRange) {
                const fullCryptoKey = await crypto.subtle.importKey(
                    'raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']
                );
                let currentBlockNum = 0;
                let skipBytes = startByte;
                const fullTransform = new TransformStream({
                    async transform(chunk, controller) {
                        const data = new Uint8Array(chunk);
                        const alignedLen = Math.floor(data.length / 16) * 16;
                        if (alignedLen === 0) return;
                        const ctr = buildCounter(baseNonce, currentBlockNum);
                        currentBlockNum += alignedLen / 16;
                        const decBuf = await crypto.subtle.decrypt(
                            { name: 'AES-CTR', counter: ctr, length: 64 },
                            fullCryptoKey, data.subarray(0, alignedLen)
                        );
                        let decrypted = new Uint8Array(decBuf);
                        if (skipBytes > 0) {
                            if (skipBytes >= decrypted.length) {
                                skipBytes -= decrypted.length;
                                return;
                            }
                            decrypted = decrypted.subarray(skipBytes);
                            skipBytes = 0;
                        }
                        if (decrypted.length > 0) controller.enqueue(decrypted);
                    }
                });
                delete respHeaders['Content-Range'];
                respHeaders['Content-Length'] = String(fileSize);
                const decrypted = fileResp.body.pipeThrough(fullTransform);
                return new Response(decrypted, { status: 200, headers: respHeaders });
            }
            const cryptoKey = await crypto.subtle.importKey(
                'raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']
            );
            // ---- buffer-list streaming decryption ----
            let currentBlockNum = startBlockNum;
            let skipBytes       = blockOffset;
            let buffers       = [];
            let totalBuffered = 0;
            const mergeBuffers = () => {
                if (buffers.length === 0) return new Uint8Array(0);
                if (buffers.length === 1) return buffers[0];
                const merged = new Uint8Array(totalBuffered);
                let pos = 0;
                for (const buf of buffers) { merged.set(buf, pos); pos += buf.length; }
                return merged;
            };
            const transformStream = new TransformStream({
                transform: async (chunk, controller) => {
                    try {
                        buffers.push(new Uint8Array(chunk));
                        totalBuffered += chunk.length;
                        const alignedLen = Math.floor(totalBuffered / 16) * 16;
                        if (alignedLen === 0) return;
                        const merged   = mergeBuffers();
                        const toDecrypt = merged.subarray(0, alignedLen);
                        const remainder = totalBuffered - alignedLen;
                        if (remainder > 0) {
                            buffers       = [merged.slice(alignedLen)];
                            totalBuffered = remainder;
                        } else {
                            buffers       = [];
                            totalBuffered = 0;
                        }
                        const counter = buildCounter(baseNonce, currentBlockNum);
                        currentBlockNum += alignedLen / 16;
                        const decBuf = await crypto.subtle.decrypt(
                            { name: 'AES-CTR', counter, length: 64 },
                            cryptoKey, toDecrypt
                        );
                        let decrypted = new Uint8Array(decBuf);
                        if (skipBytes > 0) {
                            decrypted = decrypted.subarray(skipBytes);
                            skipBytes = 0;
                        }
                        if (decrypted.length > 0) controller.enqueue(decrypted);
                    } catch (e) {
                        console.error('Mega: Transform error:', e);
                        controller.error(e);
                    }
                },
                flush: async (controller) => {
                    try {
                        if (totalBuffered > 0) {
                            const merged  = mergeBuffers();
                            const counter = buildCounter(baseNonce, currentBlockNum);
                            const decBuf = await crypto.subtle.decrypt(
                                { name: 'AES-CTR', counter, length: 64 },
                                cryptoKey, merged
                            );
                            let decrypted = new Uint8Array(decBuf);
                            if (skipBytes > 0) {
                                decrypted = decrypted.subarray(skipBytes);
                            }
                            if (decrypted.length > 0) controller.enqueue(decrypted);
                        }
                    } catch (e) {
                        console.error('Mega: Flush error:', e);
                        controller.error(e);
                    } finally {
                        buffers       = null;
                        totalBuffered = 0;
                    }
                }
            });
            const decryptedStream = fileResp.body.pipeThrough(transformStream);
            return new Response(decryptedStream, {
                status: statusCode,
                headers: respHeaders
            });
        } catch (e) {
            console.error('Mega: Download error:', e);
            return new Response('Download error: ' + e.message, { status: 500 });
        }
    }

    // ===================== TS / HLS probing =====================
    // Robust MPEG-TS probe utilities
    static _tsFindSync(buf, start = 0) {
        const limit = Math.min(buf.length - 188 * 3, 1024);
        for (let i = start; i < limit; i++) {
            if (buf[i] === 0x47 && buf[i+188] === 0x47 && buf[i+376] === 0x47) {
                return i;
            }
        }
        return -1;
    }

    static _tsParsePts(buf, off) {
        if (off + 14 > buf.length) return null;
        if (buf[off] !== 0x00 || buf[off + 1] !== 0x00 || buf[off + 2] !== 0x01) return null;
        const ptsDtsFlags = (buf[off + 7] & 0xC0) >> 6;
        if (ptsDtsFlags === 0) return null;

        const ptsOff = off + 9;
        if (ptsOff + 5 > buf.length) return null;

        const b0 = buf[ptsOff];
        const b1 = buf[ptsOff + 1];
        const b2 = buf[ptsOff + 2];
        const b3 = buf[ptsOff + 3];
        const b4 = buf[ptsOff + 4];

        return (
            (BigInt((b0 >> 1) & 0x07) << 30n) |
            (BigInt(((b1 << 8) | b2) >> 1) << 15n) |
            BigInt(((b3 << 8) | b4) >> 1)
        );
    }

    static _tsParsePcr(buf, off) {
        // Parse PCR from adaptation field, returns BigInt 27MHz ticks or null
        if (off + 188 > buf.length) return null;
        if (buf[off] !== 0x47) return null;
        const adaptation = (buf[off + 3] & 0x30) >> 4;
        if (adaptation !== 2 && adaptation !== 3) return null;
        const adaptLen = buf[off + 4];
        if (adaptLen < 7 || adaptLen > 183) return null;
        if (off + 5 + adaptLen > off + 188) return null;
        const flags = buf[off + 5];
        if ((flags & 0x10) === 0) return null; // PCR flag
        const b = off + 6;
        if (b + 6 > buf.length) return null;
        const pcrBase =
            (BigInt(buf[b]) << 25n) |
            (BigInt(buf[b+1]) << 17n) |
            (BigInt(buf[b+2]) << 9n) |
            (BigInt(buf[b+3]) << 1n) |
            (BigInt(buf[b+4]) >> 7n);
        const pcrExt = ((BigInt(buf[b+4]) & 1n) << 8n) | BigInt(buf[b+5]);
        return pcrBase * 300n + pcrExt; // 27 MHz
    }

    static _tsScanTimestamps(buf) {
        const sync = this._tsFindSync(buf, 0);
        if (sync < 0) return [];
        const samples = [];
        const packetCount = Math.floor((buf.length - sync) / 188);
        for (let i = 0; i < packetCount; i++) {
            const off = sync + i * 188;
            if (off + 188 > buf.length) continue;
            if (buf[off] !== 0x47) continue;
            const pid = ((buf[off + 1] & 0x1f) << 8) | buf[off + 2];
            if (pid === 0 || pid === 0x1FFF) continue;
            const adaptation = (buf[off + 3] & 0x30) >> 4;
            if (adaptation === 2 || adaptation === 3) {
                const pcr = this._tsParsePcr(buf, off);
                if (pcr !== null) samples.push({ type: 'pcr', ts: pcr, byte: off, clock: 27000000n });
            }
            if (adaptation === 0 || adaptation === 2) continue;

            let payloadStart = off + 4;
            if (adaptation === 3) {
                const adaptLen = buf[off + 4];
                payloadStart = off + 5 + adaptLen;
                if (payloadStart >= off + 188) continue;
            }
            const pusi = (buf[off + 1] & 0x40) !== 0;
            if (!pusi) continue;
            if (payloadStart + 14 > buf.length) continue;
            if (!(buf[payloadStart] === 0x00 && buf[payloadStart+1] === 0x00 && buf[payloadStart+2] === 0x01)) continue;
            const streamID = buf[payloadStart + 3];
            const isVideo = streamID >= 0xE0 && streamID <= 0xEF;
            const isAudio = streamID >= 0xC0 && streamID <= 0xDF;
            if (!isVideo && !isAudio) continue;
            const pts = this._tsParsePts(buf, payloadStart);
            if (pts !== null) {
                samples.push({ type: 'pts', ts: pts, byte: payloadStart, clock: 90000n });
            }
        }
        return samples;
    }

    static _tsBitrateFromSamples(samples) {
        return this._tsAnalyzeSamples(samples).bitrate;
    }

    static _tsAnalyzeSamples(samples) {
        if (samples.length < 2) return { bitrate: 0, totalDuration: 0 };
        let use = samples.filter(s => s.type === 'pts');
        if (use.length < 2) use = samples;
        if (use.length < 2) return { bitrate: 0, totalDuration: 0 };

        const first = use[0];
        const last = use[use.length - 1];
        if (first.clock !== last.clock) return { bitrate: 0, totalDuration: 0 };

        let t0 = first.ts;
        let t1 = last.ts;
        const clock = first.clock;
        const wrap = first.type === 'pts' ? (1n << 33n) : (1n << 42n);
        if (t1 < t0) t1 += wrap;

        const deltaTs = t1 - t0;
        if (deltaTs <= 0n) return { bitrate: 0, totalDuration: 0 };
        const durationSec = Number(deltaTs) / Number(clock);
        if (durationSec < 0.05) return { bitrate: 0, totalDuration: 0 };

        const byteSpan = Math.abs(last.byte - first.byte);
        if (byteSpan < 1880) return { bitrate: 0, totalDuration: 0 };
        const bitrate = Math.round((byteSpan * 8) / durationSec);
        if (bitrate < 32000 || bitrate > 200_000_000) return { bitrate: 0, totalDuration: 0 };
        return { bitrate, totalDuration: durationSec };
    }

    async probeMPEGTS(fileId, downloadUrlHint = null) {
        if (!this.initialized) await this.init();
        const node = this.nodes.get(fileId);
        if (!node) return false;
        let downloadUrl = downloadUrlHint;
        if (!downloadUrl) {
            let params = '';
            if (this.isPublicFolder) params = '&n=' + this.folderHandle;
            const resp = await this.apiRequest([{ a: 'g', g: 1, n: fileId }], params);
            if (!resp?.[0]?.g) return false;
            downloadUrl = resp[0].g;
        }

        const fileKey = node.key;
        const fileSize = node.size || node.s || 0;
        const PROBE_SIZE = 188 * 300;
        const hasVideo = (data) => MegaDrive._tsScanTimestamps(data).length > 0;

        if (fileSize > 0) {
            const data = await this._megaFetchDecryptedRange(downloadUrl, fileKey, 0, Math.min(PROBE_SIZE, fileSize), fileSize);
            return data ? hasVideo(data) : false;
        }

        const probeResp = await fetch(downloadUrl, { headers: { 'Range': `bytes=0-${PROBE_SIZE - 1}` } });
        if (!probeResp.ok && probeResp.status !== 206) return false;
        return hasVideo(new Uint8Array(await probeResp.arrayBuffer()));
    }

    async _megaFetchDecryptedRange(downloadUrl, fileKey, offset, size, fileSize) {
        if (!fileSize || fileSize <= 0) return null;
        if (offset < 0 || offset >= fileSize) return null;
        const rangeEnd = Math.min(offset + size - 1, fileSize - 1);
        if (rangeEnd < offset) return null;

        if (fileKey && fileKey.length >= 8) {
            const blockStart = Math.floor(offset / 16) * 16;
            const encResp = await fetch(downloadUrl, { headers: { 'Range': `bytes=${blockStart}-${rangeEnd}` } });
            if (!encResp.ok && encResp.status !== 206) return null;
            const encData = new Uint8Array(await encResp.arrayBuffer());
            if (encData.length === 0) return null;

            const aesKey = [
                (fileKey[0] ^ fileKey[4]) >>> 0, (fileKey[1] ^ fileKey[5]) >>> 0,
                (fileKey[2] ^ fileKey[6]) >>> 0, (fileKey[3] ^ fileKey[7]) >>> 0
            ];
            const keyBytes = new Uint8Array(16);
            for (let i = 0; i < 4; i++) {
                keyBytes[i*4]   = (aesKey[i] >>> 24) & 0xff;
                keyBytes[i*4+1] = (aesKey[i] >>> 16) & 0xff;
                keyBytes[i*4+2] = (aesKey[i] >>> 8)  & 0xff;
                keyBytes[i*4+3] =  aesKey[i]         & 0xff;
            }

            const baseNonce = new Uint8Array(8);
            baseNonce[0] = (fileKey[4] >>> 24) & 0xff; baseNonce[1] = (fileKey[4] >>> 16) & 0xff;
            baseNonce[2] = (fileKey[4] >>> 8)  & 0xff; baseNonce[3] =  fileKey[4]         & 0xff;
            baseNonce[4] = (fileKey[5] >>> 24) & 0xff; baseNonce[5] = (fileKey[5] >>> 16) & 0xff;
            baseNonce[6] = (fileKey[5] >>> 8)  & 0xff; baseNonce[7] =  fileKey[5]         & 0xff;
            const blockNum = Math.floor(blockStart / 16);
            const counter = new Uint8Array(16);
            counter.set(baseNonce, 0);
            const high = Math.floor(blockNum / 0x100000000);
            const low  = blockNum >>> 0;
            counter[8]  = (high >>> 24) & 0xff; counter[9]  = (high >>> 16) & 0xff;
            counter[10] = (high >>> 8)  & 0xff; counter[11] =  high         & 0xff;
            counter[12] = (low >>> 24)  & 0xff; counter[13] = (low >>> 16) & 0xff;
            counter[14] = (low >>> 8)   & 0xff; counter[15] =  low          & 0xff;

            const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']);
            const decBuf = new Uint8Array(await crypto.subtle.decrypt(
                { name: 'AES-CTR', counter, length: 64 }, cryptoKey, encData
            ));
            const blockOffset = offset - blockStart;
            return decBuf.slice(blockOffset, blockOffset + size);
        }

        const resp = await fetch(downloadUrl, { headers: { 'Range': `bytes=${offset}-${rangeEnd}` } });
        if (!resp.ok && resp.status !== 206) return null;
        return new Uint8Array(await resp.arrayBuffer());
    }

    async probeHLS(fileId) {
        if (!this.initialized) await this.init();
        const node = this.nodes.get(fileId);
        if (!node) return { isTS: false, bitrate: 0, totalDuration: 0 };
        let params = '';
        if (this.isPublicFolder) params = '&n=' + this.folderHandle;
        const resp = await this.apiRequest([{ a: 'g', g: 1, n: fileId }], params);
        if (!resp?.[0]?.g) return { isTS: false, bitrate: 0, totalDuration: 0 };
        const downloadUrl = resp[0].g;
        const fileSize = resp[0].s || node.size || node.s || 0;
        const cacheKey = `${fileId}:${fileSize}`;
        const cached = this.hlsProbeCache.get(cacheKey);
        if (cached && Date.now() - cached.ts < 300000) return cached.value;

        const isTS = await this.probeMPEGTS(fileId, downloadUrl);
        if (!isTS) return { isTS: false, bitrate: 0, totalDuration: 0 };
        const { bitrate, totalDuration } = await this.probeFileStats(fileId, downloadUrl, fileSize);
        const value = { isTS: true, bitrate, totalDuration };
        this.hlsProbeCache.set(cacheKey, { ts: Date.now(), value });
        return value;
    }

    async probeFileStats(fileId, downloadUrlHint = null, fileSizeHint = 0) {
        if (!this.initialized) await this.init();
        const node = this.nodes.get(fileId);
        if (!node) return { bitrate: 0, totalDuration: 0 };
        let downloadUrl = downloadUrlHint;
        let fileSize = fileSizeHint || node.size || node.s || 0;
        const fileKey = node.key;
        if (!downloadUrl) {
            let params = '';
            if (this.isPublicFolder) params = '&n=' + this.folderHandle;
            const resp = await this.apiRequest([{ a: 'g', g: 1, n: fileId }], params);
            if (!resp?.[0]?.g) return { bitrate: 0, totalDuration: 0 };
            downloadUrl = resp[0].g;
            fileSize = resp[0].s || fileSize || node.size || node.s || 0;
        }

        const PROBE = 188 * 4000;
        let bestBitrate = 0;
        let totalDuration = 0;
        let earliestTs = null;
        let latestTs = null;
        let earliestClock = null;
        let latestClock = null;

        const data1 = await this._megaFetchDecryptedRange(downloadUrl, fileKey, 0, Math.min(PROBE, fileSize), fileSize);
        if (data1) {
            const s1 = MegaDrive._tsScanTimestamps(data1);
            if (s1.length > 0) {
                const first1 = s1[0];
                earliestTs = first1.ts;
                earliestClock = first1.clock || 90000n;
                if (s1.length >= 2) {
                    const r = MegaDrive._tsAnalyzeSamples(s1);
                    if (r.bitrate > 0) bestBitrate = r.bitrate;
                }
            }
        }

        if (fileSize > 2_000_000) {
            const mid = Math.floor(fileSize / 2);
            const data2 = await this._megaFetchDecryptedRange(downloadUrl, fileKey, mid, Math.min(PROBE, fileSize - mid), fileSize);
            if (data2) {
                const s2 = MegaDrive._tsScanTimestamps(data2);
                if (s2.length >= 2) {
                    const r = MegaDrive._tsAnalyzeSamples(s2);
                    if (r.bitrate > 0 && bestBitrate === 0) bestBitrate = r.bitrate;
                }
            }
        }

        if (fileSize > 500_000) {
            const endStart = Math.max(0, fileSize - PROBE);
            const data3 = await this._megaFetchDecryptedRange(downloadUrl, fileKey, endStart, Math.min(PROBE, fileSize - endStart), fileSize);
            if (data3) {
                const s3 = MegaDrive._tsScanTimestamps(data3);
                if (s3.length > 0) {
                    const last3 = s3[s3.length - 1];
                    latestTs = last3.ts;
                    latestClock = last3.clock || 90000n;
                }
            }
        }

        if (earliestTs !== null && latestTs !== null && earliestClock !== null && latestClock !== null && earliestClock === latestClock) {
            let t0 = earliestTs;
            let t1 = latestTs;
            const wrap = earliestClock === 90000n ? (1n << 33n) : (1n << 42n);
            if (t1 < t0) t1 += wrap;
            const delta = t1 - t0;
            if (delta > 0n) totalDuration = Number(delta) / Number(earliestClock);
        }

        if (bestBitrate === 0 && totalDuration > 0 && fileSize > 0) {
            bestBitrate = Math.round((fileSize * 8) / totalDuration);
        }
        return { bitrate: bestBitrate, totalDuration };
    }

    async probeBitrate(fileId, downloadUrlHint = null, fileSizeHint = 0) {
        const { bitrate } = await this.probeFileStats(fileId, downloadUrlHint, fileSizeHint);
        return bitrate;
    }

    // ===================== search =====================
    async search(keyword, pageToken = null, pageIndex = 0) {
        if (!this.initialized) await this.init();
        const files = [];
        const lower = keyword.toLowerCase();
        for (const [, node] of this.nodes) {
            if (node.type === 0 && node.name.toLowerCase().includes(lower)) {
                files.push({
                    id:   node.id,
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

// ===================== INIT HELPER =====================
async function initMegaDrives() {
    const drives = [];
    if (megaConfig.enabled) {
        for (let i = 0; i < (megaConfig.roots?.length || 0); i++) {
            const drive = new MegaDrive(megaConfig, drives.length, megaConfig.roots[i], megaConfig.accounts?.[i] || null);
            await drive.init();
            drives.push(drive);
        }
        for (let i = 0; i < (megaConfig.accounts?.length || 0); i++) {
            const accountRoot = {
                id: `account-${i}`,
                name: megaConfig.accounts[i].email || `MEGA Account ${i + 1}`,
                public: true
            };
            const drive = new MegaDrive(megaConfig, drives.length, accountRoot, megaConfig.accounts[i]);
            await drive.init();
            drives.push(drive);
        }
    }
    return drives;
}

export { MegaDrive, MegaCrypto, initMegaDrives };
