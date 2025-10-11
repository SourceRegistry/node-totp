import { describe, it, expect } from 'vitest';
import totp, { generateURI, verifyToken, generateToken, base32 } from '../src';
import { randomBytes } from "crypto";

// RFC 6238 Appendix B test vectors (SHA1, 8 digits)
const RFC6238_VECTORS = [
    { time: 59, totp: '94287082' },
    { time: 1111111109, totp: '07081804' },
    { time: 1111111111, totp: '14050471' },
    { time: 1234567890, totp: '89005924' },
    { time: 2000000000, totp: '69279037' },
    { time: 20000000000, totp: '65353130' },
];

const SECRET_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"

describe('TOTP Library', () => {
    describe('base32', () => {
        it('should encode/decode roundtrip correctly', () => {
            const inputs = [
                Buffer.from(''),
                Buffer.from('f'),
                Buffer.from('fo'),
                Buffer.from('foo'),
                Buffer.from('foob'),
                Buffer.from('fooba'),
                Buffer.from('foobar'),
                randomBytes(20),
                randomBytes(32),
                randomBytes(64),
            ];

            for (const input of inputs) {
                const encoded = base32.encode(input);
                const decoded = base32.decode(encoded);
                expect(decoded).toEqual(input);
            }
        });

        it('should handle padding correctly', () => {
            const buf = Buffer.from([1, 2, 3]);
            const encoded = base32.encode(buf);
            expect(encoded.endsWith('==')).toBe(true);
            expect(base32.decode(encoded)).toEqual(buf);
        });

        it('should reject invalid characters', () => {
            expect(() => base32.decode('ABc123')).toThrow('Invalid base32 character');
            expect(() => base32.decode('AB$')).toThrow('Invalid base32 character');
        });

        it('should ignore padding during decode', () => {
            const clean = base32.encode(Buffer.from('test'));
            const withPadding = clean + '====';
            expect(base32.decode(withPadding)).toEqual(base32.decode(clean));
        });
    });

    describe('generateURI', () => {
        it('should generate valid URI with auto-generated secret', () => {
            const { uri, secret } = generateURI({
                issuer: 'Example',
                account: 'user@example.com',
            });
            expect(uri).toMatch(/^otpauth:\/\/totp\/Example:user%40example\.com\?/);
            expect(uri).toContain('issuer=Example');
            expect(uri).toContain('algorithm=SHA1');
            expect(uri).toContain('digits=6');
            expect(uri).toContain('period=30');
            expect(secret).toMatch(/^[A-Z2-7]+$/);
            expect(base32.decode(secret)).toHaveLength(20);
        });

        it('should use algorithm-appropriate secret length', () => {
            const sha1 = generateURI({ issuer: 'Test', account: 'a', algorithm: 'SHA1' });
            expect(base32.decode(sha1.secret)).toHaveLength(20);

            const sha256 = generateURI({ issuer: 'Test', account: 'a', algorithm: 'SHA256' });
            expect(base32.decode(sha256.secret)).toHaveLength(32);

            const sha512 = generateURI({ issuer: 'Test', account: 'a', algorithm: 'SHA512' });
            expect(base32.decode(sha512.secret)).toHaveLength(64);
        });

        it('should accept custom byteLength', () => {
            const { secret } = generateURI({
                issuer: 'Test',
                account: 'a',
                byteLength: 16,
            });
            expect(base32.decode(secret)).toHaveLength(16);
        });

        it('should accept and normalize custom secret', () => {
            const { uri } = generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'jbswy3dpehpk3pxp==', // lowercase + padding
            });
            expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
        });

        it('should validate inputs strictly', () => {
            expect(() => generateURI({ issuer: '', account: 'test' })).toThrow();
            expect(() => generateURI({ issuer: 'Test', account: '' })).toThrow();
            expect(() => generateURI({ issuer: 'Test', account: 'test', algorithm: 'MD5' as any })).toThrow();
            expect(() => generateURI({ issuer: 'Test', account: 'test', digits: 5 as any })).toThrow();
            expect(() => generateURI({ issuer: 'Test', account: 'test', period: -1 })).toThrow();
            expect(() => generateURI({ issuer: 'Test', account: 'test', byteLength: -5 })).toThrow();
        });

        it('should URI-encode special characters', () => {
            const { uri } = generateURI({
                issuer: 'My App Inc.',
                account: 'user+test@example.com',
            });
            expect(uri).toContain('My%20App%20Inc.');
            expect(uri).toContain('user%2Btest%40example.com');
        });

        it('should validate secret format strictly', () => {
            // Test via generateURI with invalid secrets
            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: ''
            })).toThrow('Invalid secret');

            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'invalid!'
            })).toThrow('Invalid secret');

            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'abc123' // lowercase + numbers outside 2-7
            })).toThrow('Invalid secret');

            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'ABCDEFGH1' // contains '1' which is invalid
            })).toThrow('Invalid secret');

            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'ABCDEFGH8' // contains '8' which is invalid
            })).toThrow('Invalid secret');

            // Valid secrets should work
            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'JBSWY3DPEHPK3PXP'
            })).not.toThrow();

            expect(() => generateURI({
                issuer: 'Test',
                account: 'test',
                secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' // full charset
            })).not.toThrow();
        });

    });

    describe('generateToken', () => {
        it('should match RFC 6238 test vectors (SHA1, 8 digits)', () => {
            const secretBuf = base32.decode(SECRET_BASE32);
            for (const { time, totp: expected } of RFC6238_VECTORS) {
                const counter = Math.floor(time / 30);
                const token = generateToken(secretBuf, counter, 8, 'SHA1');
                expect(token).toBe(expected);
            }
        });

        it('should support different algorithms and digits', () => {
            const secret = randomBytes(32);
            const counter = 12345;

            // Test all combinations
            for (const algo of ['SHA1', 'SHA256', 'SHA512'] as const) {
                for (const digits of [6, 7, 8] as const) {
                    const token = generateToken(secret, counter, digits, algo);
                    expect(token).toMatch(/^\d+$/);
                    expect(token).toHaveLength(digits);
                }
            }
        });

        it('should reject unsafe counters', () => {
            const secret = randomBytes(20);
            expect(() => generateToken(secret, -1, 6, 'SHA1')).toThrow();
            expect(() => generateToken(secret, Number.MAX_SAFE_INTEGER + 1, 6, 'SHA1')).toThrow();
        });
    });

    describe('verifyToken', () => {
        it('should verify RFC 6238 tokens correctly', () => {
            for (const { time, totp: token } of RFC6238_VECTORS) {
                const valid = verifyToken(token, SECRET_BASE32, {
                    period: 30,
                    algorithm: 'SHA1',
                    digits: 8,
                    window: 0,
                    now: time,
                });
                expect(valid).toBe(true);
            }
        });

        it('should reject invalid tokens', () => {
            expect(verifyToken('000000', SECRET_BASE32, { digits: 8, window: 0, now: 59 })).toBe(false);
            expect(verifyToken('9428708', SECRET_BASE32, { digits: 8, window: 0, now: 59 })).toBe(false); // 7 digits vs expected 8
            expect(verifyToken('94287083', SECRET_BASE32, { digits: 8, window: 0, now: 59 })).toBe(false);
        });

        it('should respect time window', () => {
            const time = 1111111111; // This time produces counter 37037037
            const secretBuf = base32.decode(SECRET_BASE32);

            // Generate the CORRECT token for this exact time
            const correctToken = generateToken(secretBuf, Math.floor(time / 30), 8, 'SHA1');

            // Exact match
            expect(verifyToken(correctToken, SECRET_BASE32, {
                digits: 8,
                window: 0,
                now: time
            })).toBe(true);

            // One period before (window=0 → fail)
            expect(verifyToken(correctToken, SECRET_BASE32, {
                digits: 8,
                window: 0,
                now: time - 30
            })).toBe(false);

            // But succeed with window=1
            expect(verifyToken(correctToken, SECRET_BASE32, {
                digits: 8,
                window: 1,
                now: time - 30
            })).toBe(true);

            // One period after
            expect(verifyToken(correctToken, SECRET_BASE32, {
                digits: 8,
                window: 1,
                now: time + 30
            })).toBe(true);
        });

        it('should skip negative time steps', () => {
            // At time=0, window=2 would try steps -2, -1, 0 → skip negatives
            const secret = base32.encode(randomBytes(20));
            const tokenAt0 = generateToken(base32.decode(secret), 0, 6, 'SHA1');
            expect(verifyToken(tokenAt0, secret, { digits: 6, window: 2, now: 0 })).toBe(true);
        });

        it('should use constant-time comparison', () => {
            // This test ensures we don't leak info via timing
            // We can't measure timing in unit tests, but we verify logic
            const secret = SECRET_BASE32;
            const validToken = '94287082';
            const invalidSameLen = '94287081';
            const invalidDiffLen = '123456'; // 6 digits

            // Must specify digits: 8 for 8-digit tokens!
            expect(verifyToken(validToken, secret, { digits: 8, now: 59 })).toBe(true);
            expect(verifyToken(invalidSameLen, secret, { digits: 8, now: 59 })).toBe(false);
            expect(verifyToken(invalidDiffLen, secret, { digits: 8, now: 59 })).toBe(false);
        });

        it('should validate options strictly', () => {
            expect(() => verifyToken('123456', SECRET_BASE32, { window: -1 })).toThrow();
            expect(() => verifyToken('123456', SECRET_BASE32, { period: 0 })).toThrow();
            expect(() => verifyToken('123456', SECRET_BASE32, { algorithm: 'MD5' as any })).toThrow();
        });

        it('should handle different digit lengths', () => {
            const secret = base32.encode(randomBytes(20));
            const counter = 1000;
            const time = counter * 30;

            const token6 = generateToken(base32.decode(secret), counter, 6, 'SHA1');
            const token8 = generateToken(base32.decode(secret), counter, 8, 'SHA1');

            // Correct: match when digits option matches token length
            expect(verifyToken(token6, secret, { digits: 6, now: time })).toBe(true);
            expect(verifyToken(token8, secret, { digits: 8, now: time })).toBe(true);

            // Mismatch: token6 has 6 digits, but we expect 8 → should fail
            expect(verifyToken(token6, secret, { digits: 8, now: time })).toBe(false);
            // Also: token8 passed to 6-digit verifier → fail
            expect(verifyToken(token8, secret, { digits: 6, now: time })).toBe(false);
        });

        it('should reject tokens with invalid format', () => {
            const secret = 'JBSWY3DPEHPK3PXP';

            // Too short (< 6 digits)
            expect(verifyToken('12345', secret)).toBe(false);
            expect(verifyToken('1234', secret)).toBe(false);
            expect(verifyToken('123', secret)).toBe(false);
            expect(verifyToken('12', secret)).toBe(false);
            expect(verifyToken('1', secret)).toBe(false);
            expect(verifyToken('', secret)).toBe(false);

            // Too long (> 8 digits)
            expect(verifyToken('123456789', secret)).toBe(false);
            expect(verifyToken('1234567890', secret)).toBe(false);
            expect(verifyToken('123456789012345', secret)).toBe(false);

            // Non-digit characters
            expect(verifyToken('12345a', secret)).toBe(false);
            expect(verifyToken('123456!', secret)).toBe(false);
            expect(verifyToken('123 456', secret)).toBe(false);
            expect(verifyToken('123-456', secret)).toBe(false);
            expect(verifyToken('abcdef', secret)).toBe(false);
            expect(verifyToken('12.345', secret)).toBe(false);
        });

        it('should validate secret format in verifyToken', () => {
            // Empty/invalid secrets
            expect(() => verifyToken('123456', '')).toThrow('Invalid secret');
            expect(() => verifyToken('123456', 'invalid!')).toThrow('Invalid secret');
            expect(() => verifyToken('123456', 'abc123')).toThrow('Invalid secret');
            expect(() => verifyToken('123456', 'ABCDEFGH1')).toThrow('Invalid secret');

            // Valid secret should not throw (but token will be invalid)
            expect(() => verifyToken('123456', 'JBSWY3DPEHPK3PXP')).not.toThrow();
        });

    });

    describe('Integration', () => {
        it('should generate and verify a full flow', () => {
            const { secret } = generateURI({
                issuer: 'IntegrationTest',
                account: 'test@example.com',
                algorithm: 'SHA256',
                digits: 7,
                period: 45,
            });

            const now = Math.floor(Date.now() / 1000);
            const token = generateToken(base32.decode(secret), Math.floor(now / 45), 7, 'SHA256');

            const isValid = verifyToken(token, secret, {
                algorithm: 'SHA256',
                digits: 7,
                period: 45,
                window: 1,
            });
            expect(isValid).toBe(true);
        });
    });
    describe('Validation Methods', () => {
        it('should validate secret format correctly', () => {
            const validSecrets = [
                'A',
                'Z',
                '2',
                '7',
                'JBSWY3DPEHPK3PXP',
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                'MFRGGZDFMZTWQ2LJ'
            ];

            const invalidSecrets = [
                '',
                ' ',
                'a', // lowercase
                '1', // invalid digit
                '8', // invalid digit
                '9', // invalid digit
                '0', // invalid digit
                'ABC DEF', // space
                'ABC-DEF', // hyphen
                'ABC_DEF', // underscore
                'ABCDEFGH!', // special char
                null as any,
                undefined as any
            ];

            for (const secret of validSecrets) {
                expect(() => totp.validate.secret(secret)).not.toThrow();
            }

            for (const secret of invalidSecrets) {
                expect(() => totp.validate.secret(secret)).toThrow('Invalid secret');
            }
        });
    });
});
