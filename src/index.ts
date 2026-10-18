import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

/**
 * Supported HMAC algorithms for TOTP generation and verification.
 */
export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

/**
 * Supported token lengths for generated TOTP codes.
 */
export type TotpDigits = 6 | 7 | 8;
export type UriDigits = 6 | 8;

/** Atomically claim a matched time-step counter for one enrolled account. */
export type ClaimTotpCounter = (counter: number) => boolean | Promise<boolean>;

const MIN_SECRET_BYTES = 16;
const MAX_WINDOW = 2;

/**
 * RFC 4648 Base32 helpers exposed by the public API.
 */
export interface Base32Api {
    /**
     * The canonical RFC 4648 Base32 alphabet.
     */
    readonly charset: string;

    /**
     * Encodes a buffer as padded RFC 4648 Base32.
     *
     * @param buffer Bytes to encode.
     * @returns The padded Base32 string.
     */
    encode(buffer: Buffer): string;

    /**
     * Decodes a canonical RFC 4648 Base32 string.
     *
     * @param base32Str Base32 input to decode.
     * @returns The decoded bytes.
     * @throws If the string contains invalid characters or non-canonical encoding.
     */
    decode(base32Str: string): Buffer;
}

/**
 * Options for generating an otpauth URI and secret.
 */
export interface GenerateUriOptions {
    /**
     * Service or application name displayed by authenticator apps.
     */
    issuer: string;

    /**
     * User identifier, typically an email address or username.
     */
    account: string;

    /**
     * Canonical unpadded Base32 secret of at least 16 bytes to embed in the URI.
     * If omitted, a new secret is generated.
     */
    secret?: string;

    /**
     * Hash algorithm used by the authenticator.
     *
     * @defaultValue `'SHA1'`
     */
    algorithm?: TotpAlgorithm;

    /**
     * Number of digits in the setup URI (6 or 8).
     *
     * @defaultValue `6`
     */
    digits?: UriDigits;

    /**
     * Time step in seconds.
     *
     * @defaultValue `30`
     */
    period?: number;

    /**
     * Secret length in bytes when generating a new secret (minimum 16).
     * Defaults to an algorithm-appropriate size.
     */
    byteLength?: number;
}

/**
 * Result returned when generating an otpauth URI.
 */
export interface GenerateUriResult {
    /**
     * Fully encoded otpauth URI suitable for authenticator setup.
     */
    uri: string;

    /**
     * Canonical unpadded Base32 secret associated with the URI.
     */
    secret: string;
}

/**
 * Options that control TOTP token verification.
 */
export interface VerifyTokenOptions {
    /**
     * Number of time steps to check before and after the current step (0 to 2).
     */
    window: number;

    /**
     * Time step in seconds.
     */
    period: number;

    /**
     * Hash algorithm expected for the token.
     */
    algorithm: TotpAlgorithm;

    /**
     * Expected token length.
     */
    digits: TotpDigits;

    /**
     * Unix time in seconds to use instead of `Date.now()`.
     */
    now: number;
}

interface TotpHelpers {
    normalizeSecret(secret: string): string;
    generateSecret(byteLength: number): string;
}

interface TotpValidation {
    issuer(issuer: string): void;
    account(account: string): void;
    algorithm(algo: string): void;
    digits(digits: number): void;
    period(period: number): void;
    secret(secret: string): void;
}

export interface TotpApi {
    /**
     * RFC 4648 Base32 helpers.
     */
    base32: Base32Api;

    /**
     * Internal helper utilities exposed on the default export.
     */
    helpers: TotpHelpers;

    /**
     * Input validation helpers exposed on the default export.
     */
    validate: TotpValidation;

    /**
     * Generates an otpauth URI and associated secret.
     *
     * @param options TOTP configuration values.
     * @returns The generated otpauth URI and secret.
     */
    generateURI(options: GenerateUriOptions): GenerateUriResult;

    /**
     * Checks a token against a shared secret without replay protection.
     *
     * @param token User-provided token.
     * @param secret Canonical unpadded Base32 secret.
     * @param options Verification overrides.
     * @returns `true` when the token is valid for the given window.
     */
    verifyToken(token: string, secret: string, options?: Partial<VerifyTokenOptions>): boolean;

    /**
     * Verifies a token and atomically claims its matched counter.
     * The claim callback must persist the greatest accepted counter per account
     * and return true only when it advances that counter.
     */
    verifyTokenOnce(token: string, secret: string, claimCounter: ClaimTotpCounter, options?: Partial<VerifyTokenOptions>): Promise<boolean>;

    /**
     * Generates a token for a specific counter value.
     *
     * @param secret Decoded secret bytes.
     * @param counter Time-step counter.
     * @param digits Number of digits to return.
     * @param algorithm HMAC algorithm.
     * @returns A zero-padded TOTP token.
     */
    generateToken(secret: Buffer, counter: number, digits: TotpDigits, algorithm: TotpAlgorithm): string;
}

/**
 * RFC 4648 Base32 implementation
 */
export const base32: Base32Api = {
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
        const normalized = base32Str.trim().toUpperCase();
        if (normalized.length === 0) return Buffer.alloc(0);
        if (!/^[A-Z2-7]+=*$/.test(normalized)) {
            throw new Error('Invalid base32 character');
        }

        const clean = normalized.replace(/=+$/, '');
        if (clean.length === 0) return Buffer.alloc(0);

        const remainder = clean.length % 8;
        if (![0, 2, 4, 5, 7].includes(remainder)) {
            throw new Error('Invalid base32 length');
        }

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
        const decoded = Buffer.from(bytes);
        const canonical = this.encode(decoded).replace(/=+$/, '');
        if (canonical !== clean) {
            throw new Error('Invalid base32 encoding');
        }

        return decoded;
    },
};

function findMatchingCounter(api: TotpApi, token: string, inputSecret: string, options: Partial<VerifyTokenOptions>, minimumSecretBytes: number): number | null {
    const {
        window = 1,
        period = 30,
        algorithm = 'SHA1',
        digits = 6,
        now: nowOpt
    } = options;

    if (!/^\d{6,8}$/.test(token) || token.length !== digits) return null;

    const secret = api.helpers.normalizeSecret(inputSecret);
    api.validate.secret(secret);
    api.validate.algorithm(algorithm);
    api.validate.digits(digits);
    api.validate.period(period);
    if (!Number.isInteger(window) || window < 0 || window > MAX_WINDOW) {
        throw new Error(`Window must be an integer from 0 to ${MAX_WINDOW}`);
    }

    const secretBuf = base32.decode(secret);
    if (secretBuf.length < minimumSecretBytes) {
        throw new Error(`Secret must contain at least ${minimumSecretBytes} bytes`);
    }
    const nowSec = nowOpt ?? Math.floor(Date.now() / 1000);
    const currentStep = Math.floor(nowSec / period);
    const tokBuf = Buffer.from(token);

    for (let i = -window; i <= window; i++) {
        const step = currentStep + i;
        if (step < 0) continue;

        const generated = api.generateToken(secretBuf, step, digits, algorithm);
        const genBuf = Buffer.from(generated);
        if (genBuf.length === tokBuf.length && timingSafeEqual(genBuf, tokBuf)) {
            return step;
        }
    }
    return null;
}

const totp: TotpApi = {
    base32,
    helpers: {
        normalizeSecret(secret: string): string {
            return secret.trim().toUpperCase().replace(/=+$/, '');
        },
        generateSecret(byteLength: number): string {
            if (!Number.isInteger(byteLength) || byteLength < MIN_SECRET_BYTES) {
                throw new Error(`Secret byte length must be an integer of at least ${MIN_SECRET_BYTES}`);
            }
            return this.normalizeSecret(base32.encode(randomBytes(byteLength)));
        },
    },

    validate: {
        issuer(issuer: string): void {
            if (typeof issuer !== 'string' || !issuer.trim() || /[:\u0000-\u001f\u007f]/.test(issuer)) {
                throw new Error('Invalid issuer. Must be non-empty and contain no colon or control characters.');
            }
        },
        account(account: string): void {
            if (typeof account !== 'string' || !account.trim() || /[:\u0000-\u001f\u007f]/.test(account)) {
                throw new Error('Invalid account. Must be non-empty and contain no colon or control characters.');
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

            try {
                const canonical = base32.encode(base32.decode(secret)).replace(/=+$/, '');
                if (canonical !== secret) {
                    throw new Error('Invalid secret. Must be valid base32 string (A-Z2-7).');
                }
            } catch {
                throw new Error('Invalid secret. Must be valid base32 string (A-Z2-7).');
            }
        },
    },

    generateURI(options: GenerateUriOptions): GenerateUriResult {
        const {
            issuer,
            account,
            secret: inputSecret,
            algorithm = 'SHA1',
            digits = 6,
            period = 30,
            byteLength,
        } = options;

        this.validate.issuer(issuer);
        this.validate.account(account);
        this.validate.algorithm(algorithm);
        this.validate.digits(digits);
        if (digits !== 6 && digits !== 8) {
            throw new Error('URI digits must be 6 or 8');
        }
        this.validate.period(period);
        const normalizedAlgorithm = algorithm.toUpperCase() as TotpAlgorithm;

        let secret: string;
        if (inputSecret !== undefined) {
            secret = this.helpers.normalizeSecret(inputSecret);
            this.validate.secret(secret);
            if (base32.decode(secret).length < MIN_SECRET_BYTES) {
                throw new Error(`Secret must contain at least ${MIN_SECRET_BYTES} bytes`);
            }
        } else {
            const secretLength = byteLength ?? (normalizedAlgorithm === 'SHA1' ? 20 : normalizedAlgorithm === 'SHA256' ? 32 : 64);
            secret = this.helpers.generateSecret(secretLength);
        }

        const encodedIssuer = encodeURIComponent(issuer);
        const encodedAccount = encodeURIComponent(account);
        const encodedSecret = encodeURIComponent(secret);

        const uri = `otpauth://totp/${encodedIssuer}:${encodedAccount}?` +
            `issuer=${encodedIssuer}` +
            `&secret=${encodedSecret}` +
            `&algorithm=${normalizedAlgorithm}` +
            `&digits=${digits}` +
            `&period=${period}`;

        return { uri, secret };
    },

    verifyToken(token: string, secret: string, options: Partial<VerifyTokenOptions> = {}): boolean {
        return findMatchingCounter(this, token, secret, options, 0) !== null;
    },

    async verifyTokenOnce(token: string, secret: string, claimCounter: ClaimTotpCounter, options: Partial<VerifyTokenOptions> = {}): Promise<boolean> {
        if (typeof claimCounter !== 'function') {
            throw new Error('A counter claim callback is required');
        }
        const counter = findMatchingCounter(this, token, secret, options, MIN_SECRET_BYTES);
        return counter !== null && await claimCounter(counter) === true;
    },

    generateToken(
        secret: Buffer,
        counter: number,
        digits: TotpDigits,
        algorithm: TotpAlgorithm
    ): string {
        if (!Number.isSafeInteger(counter) || counter < 0) {
            throw new Error('Counter must be a non-negative safe integer');
        }
        totp.validate.digits(digits);
        totp.validate.algorithm(algorithm);

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
export const generateURI: TotpApi['generateURI'] = totp.generateURI.bind(totp);

/**
 * Verifies a token based on the configuration provided.
 */
export const verifyToken: TotpApi['verifyToken'] = totp.verifyToken.bind(totp);

/** Verifies a token once using an application-provided atomic counter claim. */
export const verifyTokenOnce: TotpApi['verifyTokenOnce'] = totp.verifyTokenOnce.bind(totp);

/**
 * Generates a token just like a password manager.
 */
export const generateToken: TotpApi['generateToken'] = totp.generateToken.bind(totp);
