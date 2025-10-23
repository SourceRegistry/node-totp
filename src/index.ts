import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

/**
 * RFC 4648 Base32 implementation
 */
export const base32 = {
    get charset(): string {
        return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    },

    encode(buffer: Buffer): string {
        if (buffer.length === 0) return '';

        let bitString = '';
        for (let i = 0; i < buffer.length; i++) {
            bitString += buffer[i].toString(2).padStart(8, '0');
        }

        let base32 = '';
        for (let i = 0; i < bitString.length; i += 5) {
            const chunk = bitString.slice(i, i + 5).padEnd(5, '0');
            const idx = parseInt(chunk, 2);
            base32 += this.charset[idx];
        }

        // Add padding
        const padding = (8 - (base32.length % 8)) % 8;
        return base32 + '='.repeat(padding);
    },

    decode(base32Str: string): Buffer {
        const clean = base32Str.replace(/=/g, '').toUpperCase();
        if (clean.length === 0) return Buffer.alloc(0);

        // Validate
        for (const char of clean) {
            if (this.charset.indexOf(char) === -1) {
                throw new Error('Invalid base32 character');
            }
        }

        let bitString = '';
        for (const char of clean) {
            const idx = this.charset.indexOf(char);
            bitString += idx.toString(2).padStart(5, '0');
        }

        // Convert to bytes (only full bytes)
        const byteLength = Math.floor(bitString.length / 8);
        const bytes = new Uint8Array(byteLength);
        for (let i = 0; i < byteLength; i++) {
            bytes[i] = parseInt(bitString.slice(i * 8, (i + 1) * 8), 2);
        }
        return Buffer.from(bytes);
    },
};

const totp = {
    helpers: {
        normalizeSecret(secret: string): string {
            return secret.trim().toUpperCase().replace(/=/g, '');
        },
        generateSecret(byteLength: number): string {
            if (!Number.isInteger(byteLength) || byteLength <= 0) {
                throw new Error('Secret byte length must be a positive integer');
            }
            return base32.encode(randomBytes(byteLength));
        },
    },

    validate: {
        issuer(issuer: string): void {
            if (!issuer || !/^[\w .-]+$/.test(issuer)) {
                throw new Error('Invalid issuer. Must contain only letters, numbers, spaces, dots, hyphens, and underscores.');
            }
        },
        account(account: string): void {
            if (!account || !/^[\w@.+-]+$/.test(account)) {
                throw new Error('Invalid account. Must contain only letters, numbers, and @ . + - _ characters.');
            }
        },
        algorithm(algo: string): void {
            if (!['SHA1', 'SHA256', 'SHA512'].includes(algo.toUpperCase())) {
                throw new Error('Invalid algorithm. Must be SHA1, SHA256, or SHA512.');
            }
        },
        digits(digits: number): void {
            if (![6, 7, 8].includes(digits)) {
                throw new Error('Invalid digits. Must be 6, 7, or 8.');
            }
        },
        period(period: number): void {
            if (!Number.isInteger(period) || period <= 0) {
                throw new Error('Invalid period. Must be a positive integer.');
            }
        },
        secret(secret: string): void {
            if (!secret || !/^[A-Z2-7]+$/.test(secret)) {
                throw new Error('Invalid secret. Must be valid base32 string (A-Z2-7).');
            }
        },
    },

    generateURI(options: {
        issuer: string;
        account: string;
        secret?: string;
        algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
        digits?: 6 | 7 | 8;
        period?: number;
        byteLength?: number;
    }) {
        const {
            issuer,
            account,
            secret: inputSecret,
            algorithm = 'SHA1',
            digits = 6,
            period = 30,
            byteLength = algorithm === 'SHA1' ? 20 : algorithm === 'SHA256' ? 32 : 64,
        } = options;

        this.validate.issuer(issuer);
        this.validate.account(account);
        this.validate.algorithm(algorithm);
        this.validate.digits(digits);
        this.validate.period(period);

        let secret: string;
        if (inputSecret !== undefined) {
            secret = this.helpers.normalizeSecret(inputSecret);
            this.validate.secret(secret);
        } else {
            secret = this.helpers.generateSecret(byteLength);
        }

        const encodedIssuer = encodeURIComponent(issuer);
        const encodedAccount = encodeURIComponent(account);
        const encodedSecret = encodeURIComponent(secret);

        const uri = `otpauth://totp/${encodedIssuer}:${encodedAccount}?` +
            `issuer=${encodedIssuer}` +
            `&secret=${encodedSecret}` +
            `&algorithm=${algorithm.toUpperCase()}` +
            `&digits=${digits}` +
            `&period=${period}`;

        return { uri, secret };
    },

    verifyToken(
        token: string,
        secret: string,
        options: Partial<{
            window: number;
            period: number;
            algorithm: 'SHA1' | 'SHA256' | 'SHA512';
            digits: 6 | 7 | 8; // ← ADD THIS
            now: number;
        }> = {}
    ): boolean {
        const {
            window = 1,
            period = 30,
            algorithm = 'SHA1',
            digits = 6, // ← DEFAULT TO 6, NOT token.length!
            now: nowOpt
        } = options;

        if (!/^\d{6,8}$/.test(token)) return false;
        if (token.length !== digits) return false; // ← CRITICAL: enforce digit length

        secret = this.helpers.normalizeSecret(secret);
        this.validate.secret(secret);
        this.validate.algorithm(algorithm);
        this.validate.digits(digits);
        this.validate.period(period);
        if (!Number.isInteger(window) || window < 0) {
            throw new Error('Window must be a non-negative integer');
        }

        const secretBuf = base32.decode(secret);
        const nowSec = nowOpt ?? Math.floor(Date.now() / 1000);
        const currentStep = Math.floor(nowSec / period);

        for (let i = -window; i <= window; i++) {
            const step = currentStep + i;
            if (step < 0) continue;

            const generated = this.generateToken(secretBuf, step, digits, algorithm);

            const genBuf = Buffer.from(generated);
            const tokBuf = Buffer.from(token);
            if (genBuf.length === tokBuf.length && timingSafeEqual(genBuf, tokBuf)) {
                return true;
            }
        }
        return false;
    },

    generateToken(
        secret: Buffer,
        counter: number,
        digits: number,
        algorithm: 'SHA1' | 'SHA256' | 'SHA512'
    ): string {
        if (!Number.isSafeInteger(counter) || counter < 0) {
            throw new Error('Counter must be a non-negative safe integer');
        }

        const counterBuf = Buffer.alloc(8);
        counterBuf.writeBigUInt64BE(BigInt(counter));

        const hash = createHmac(algorithm, secret)
            .update(counterBuf)
            .digest();

        const offset = hash[hash.length - 1] & 0xf;
        const truncated = (
            (BigInt(hash[offset] & 0x7f) << 24n) |
            (BigInt(hash[offset + 1] & 0xff) << 16n) |
            (BigInt(hash[offset + 2] & 0xff) << 8n) |
            BigInt(hash[offset + 3] & 0xff)
        );

        const code = Number(truncated % (10n ** BigInt(digits)));
        return code.toString().padStart(digits, '0');
    },
};

export default totp;

/**
 * Generates an otpauth URL that when opened launches any capable password manager that supports TOTP.
 */
export const generateURI = totp.generateURI.bind(totp);

/**
 * Verifies a token based on the configuration provided.
 */
export const verifyToken = totp.verifyToken.bind(totp);

/**
 * Generates a token just like a password manager.
 */
export const generateToken = totp.generateToken.bind(totp);
