# @sourceregistry/node-totp

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-totp)](https://www.npmjs.com/package/@sourceregistry/node-totp)
[![JSR](https://jsr.io/badges/@sourceregistry/node-totp)](https://jsr.io/@sourceregistry/node-totp)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-totp)](https://github.com/SourceRegistry/node-totp/blob/main/LICENSE)
[![Build Status](https://github.com/SourceRegistry/node-totp/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-totp/actions)
[![Coverage](https://img.shields.io/codecov/c/github/SourceRegistry/node-totp)](https://codecov.io/gh/SourceRegistry/node-totp)

A zero-dependency, RFC-compliant TOTP (Time-based One-Time Password) library for Node.js. It is intended for server-side 2FA flows with Google Authenticator, Authy, and other TOTP-compatible apps.

- RFC 6238 and RFC 4226 compliant
- Zero external dependencies
- Timing attack resistant token comparison
- TypeScript definitions included
- Tested against RFC vectors
- Strict input validation and safe defaults

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
  window: 1 // Accept tokens from +/-30 seconds
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

Generates an `otpauth://` URI and a secret for TOTP setup.

- `issuer` (string, required): Service name such as `MyApp`
- `account` (string, required): User identifier such as an email address
- `secret` (string, optional): Canonical unpadded Base32 secret
- `algorithm` (string, optional): `SHA1`, `SHA256`, or `SHA512` (default `SHA1`)
- `digits` (number, optional): `6`, `7`, or `8` (default `6`)
- `period` (number, optional): Time step in seconds (default `30`)
- `byteLength` (number, optional): Secret length in bytes

Returns `{ uri: string, secret: string }`.

### `verifyToken(token, secret, options?)`

Verifies a TOTP token against a secret.

- `token` (string): User-provided token with 6 to 8 digits
- `secret` (string): Canonical unpadded Base32 secret
- `options.window` (number): Time window in steps (default `1`, meaning +/-30 seconds with the default period)
- `options.period` (number): Time step in seconds (default `30`)
- `options.algorithm` (string): Hash algorithm (default `SHA1`)
- `options.digits` (number): Expected token length (default `6`)
- `options.now` (number): Unix timestamp in seconds, useful for testing

Returns `boolean`.

### `generateToken(secret, counter, digits, algorithm)`

Generates a TOTP token.

- `secret` (Buffer): Decoded secret buffer
- `counter` (number): Time step counter
- `digits` (number): Token length
- `algorithm` (string): Hash algorithm

Returns a zero-padded string token.

### `base32`

RFC 4648 Base32 helpers:

- `base32.encode(buffer: Buffer): string`
- `base32.decode(base32Str: string): Buffer`

The library accepts canonical unpadded Base32 secrets. Padded or non-canonical forms are normalized or rejected before use.

## Security Notes

- Token comparison uses `crypto.timingSafeEqual()`
- Supported algorithms are limited to `SHA1`, `SHA256`, and `SHA512`
- Digits are limited to `6`, `7`, or `8`
- Period must be a positive integer
- Generated secrets use algorithm-appropriate byte lengths

## Testing

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
