# @sourceregistry/node-totp

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-totp)](https://www.npmjs.com/package/@sourceregistry/node-totp)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-totp)](https://github.com/SourceRegistry/node-totp/blob/main/LICENSE)
[![Build Status](https://github.com/SourceRegistry/node-totp/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-totp/actions)
[![Coverage](https://img.shields.io/codecov/c/github/SourceRegistry/node-totp)](https://codecov.io/gh/SourceRegistry/node-totp)

A **zero-dependency**, **RFC-compliant** TOTP (Time-based One-Time Password) library for Node.js. Perfect for implementing 2FA authentication with Google Authenticator, Authy, and other TOTP-compatible apps.

- ✅ **RFC 6238 & RFC 4226 compliant**
- ✅ **Zero external dependencies** (only uses Node.js built-ins)
- ✅ **Timing attack resistant** with constant-time comparison
- ✅ **TypeScript ready** with full type definitions
- ✅ **Comprehensive test coverage** including official RFC test vectors
- ✅ **Secure by default** with input validation and safe defaults

## Installation

```bash
npm install @sourceregistry/node-totp
```

## Usage

### Basic Example

```ts
import { generateURI, verifyToken } from '@sourceregistry/node-totp';

// Generate setup URI for authenticator apps
const { uri, secret } = generateURI({
  issuer: 'MyApp',
  account: 'user@example.com',
  algorithm: 'SHA256',
  digits: 6,
  period: 30
});

console.log('Scan this URI in your authenticator app:', uri);
// otpauth://totp/MyApp:user%40example.com?issuer=MyApp&secret=...

// Later, verify user input
const userInput = '123456';
const isValid = verifyToken(userInput, secret, {
  algorithm: 'SHA256',
  digits: 6,
  period: 30,
  window: 1 // Accept tokens from ±30 seconds
});

console.log('Token valid:', isValid);
```

### Advanced Configuration

```ts
import totp from '@sourceregistry/node-totp';

// Generate with custom secret length (algorithm-appropriate defaults)
const { secret } = totp.generateURI({
  issuer: 'SecureApp',
  account: 'admin@secureapp.com',
  algorithm: 'SHA512', // Uses 64-byte secret by default
  byteLength: 48 // Override default secret length
});

// Verify with custom time (useful for testing)
const testTime = Math.floor(Date.now() / 1000);
const testToken = totp.generateToken(
  totp.base32.decode(secret), 
  Math.floor(testTime / 30), 
  6, 
  'SHA512'
);

const isValid = totp.verifyToken(testToken, secret, {
  algorithm: 'SHA512',
  digits: 6,
  period: 30,
  window: 2,
  now: testTime // Use specific timestamp instead of Date.now()
});
```

## API Reference

### `generateURI(options)`

Generates an `otpauth://` URI and secret for TOTP setup.

**Options:**
- `issuer` (string, required) - Service name (e.g., "MyApp")
- `account` (string, required) - User identifier (e.g., email)
- `secret` (string, optional) - Base32-encoded secret. If omitted, auto-generated
- `algorithm` (string, optional) - `'SHA1'` | `'SHA256'` | `'SHA512'` (default: `'SHA1'`)
- `digits` (number, optional) - `6` | `7` | `8` (default: `6`)
- `period` (number, optional) - Time step in seconds (default: `30`)
- `byteLength` (number, optional) - Secret length in bytes (default: algorithm-appropriate)

**Returns:** `{ uri: string, secret: string }`

### `verifyToken(token, secret, options?)`

Verifies a TOTP token against a secret.

**Parameters:**
- `token` (string) - User-provided token (6-8 digits)
- `secret` (string) - Base32-encoded secret
- `options` (object, optional):
    - `window` (number) - Time window in steps (default: `1` = ±30 seconds)
    - `period` (number) - Time step in seconds (default: `30`)
    - `algorithm` (string) - Hash algorithm (default: `'SHA1'`)
    - `digits` (number) - Expected token length (default: `6`)
    - `now` (number) - Unix timestamp in seconds (for testing)

**Returns:** `boolean`

### `generateToken(secret, counter, digits, algorithm)`

Generates a TOTP token (primarily for internal/testing use).

**Parameters:**
- `secret` (Buffer) - Decoded secret buffer
- `counter` (number) - Time step counter
- `digits` (number) - Token length (6, 7, or 8)
- `algorithm` (string) - Hash algorithm

**Returns:** `string` (padded token)

### `base32`

RFC 4648 Base32 implementation:

- `base32.encode(buffer: Buffer): string`
- `base32.decode(base32Str: string): Buffer`

## Security Features

### 🔒 Timing Attack Protection
Uses Node.js `crypto.timingSafeEqual()` for constant-time token comparison to prevent timing side-channel attacks.

### 🛡️ Input Validation
All inputs are strictly validated:
- Secret must be valid Base32 (A-Z2-7)
- Algorithm restricted to SHA1/SHA256/SHA512
- Digits limited to 6, 7, or 8
- Period must be positive integer
- Account/issuer names validated against safe character sets

### 🔐 Secure Defaults
- Auto-generated secrets use algorithm-appropriate lengths:
    - SHA1: 20 bytes (160 bits)
    - SHA256: 32 bytes (256 bits)
    - SHA512: 64 bytes (512 bits)
- Time window defaults to ±30 seconds (1 step)

## Testing

The library includes comprehensive tests:

- ✅ All RFC 6238 test vectors
- ✅ Base32 encode/decode roundtrip validation
- ✅ Algorithm and digit length combinations
- ✅ Time window boundary testing
- ✅ Security validation (timing safety, input validation)

Run tests with:
```bash
npm test
npm run test:coverage
```

## Examples

### QR Code Generation (with `qrcode` package)

```ts
import qrcode from 'qrcode';
import { generateURI } from '@sourceregistry/node-totp';

const { uri } = generateURI({
  issuer: 'MyApp',
  account: 'user@example.com'
});

const qrDataUrl = await qrcode.toDataURL(uri);
// Display qrDataUrl in your HTML template
```

### Express.js Integration

```ts
import express from 'express';
import { generateURI, verifyToken } from '@sourceregistry/node-totp';

const app = express();

// Setup route
app.get('/2fa/setup', (req, res) => {
  const { uri, secret } = generateURI({
    issuer: 'MyApp',
    account: req.user.email
  });
  
  // Store secret securely (encrypted) in user database
  req.user.totpSecret = secret;
  
  res.json({ uri });
});

// Verify route
app.post('/2fa/verify', (req, res) => {
  const { token } = req.body;
  const isValid = verifyToken(token, req.user.totpSecret, {
    window: 1
  });
  
  res.json({ valid: isValid });
});
```

## License

Apache-2.0 © [A.P.A. Slaa](mailto:a.p.a.slaa@projectsource.nl)

---

**Note**: This library is designed for server-side Node.js applications. For browser usage, consider using a Web Crypto API compatible alternative.
