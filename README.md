# @sourceregistry/node-totp

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-totp)](https://www.npmjs.com/package/@sourceregistry/node-totp)
[![JSR](https://jsr.io/badges/@sourceregistry/node-totp)](https://jsr.io/@sourceregistry/node-totp)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-totp)](https://github.com/SourceRegistry/node-totp/blob/main/LICENSE)
[![Build Status](https://github.com/SourceRegistry/node-totp/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-totp/actions)
[![Coverage](https://img.shields.io/codecov/c/github/SourceRegistry/node-totp)](https://codecov.io/gh/SourceRegistry/node-totp)

A zero-dependency TOTP (Time-based One-Time Password) library for Node.js. It implements the RFC 4226/6238 code calculation and generates `otpauth://` setup URIs. Full verifier compliance requires application-managed replay protection, attempt throttling, and secure per-account secret storage.

- RFC 4226/6238 code calculation, with an API for replay-safe verification
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
  digits: 6,
  period: 30
});

console.log('Scan this URI in your authenticator app:', uri);
// otpauth://totp/MyApp:user%40example.com?issuer=MyApp&secret=...

// Later, check user input (stateless; see verifyTokenOnce for login flows)
const userInput = '123456';
const isValid = verifyToken(userInput, secret, {
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

- `issuer` (string, required): Service name such as `MyApp`; cannot contain a colon or control characters
- `account` (string, required): User identifier such as an email address or `Alice Smith`; cannot contain a colon or control characters
- `secret` (string, optional): Canonical unpadded Base32 secret containing at least 16 decoded bytes
- `algorithm` (string, optional): `SHA1`, `SHA256`, or `SHA512` (default `SHA1`); casing is normalized at runtime
- `digits` (number, optional): `6` or `8` for `otpauth://` compatibility (default `6`)
- `period` (number, optional): Time step in seconds (default `30`)
- `byteLength` (number, optional): Generated secret length in bytes (minimum `16`; defaults to `20`, `32`, or `64` for SHA1, SHA256, or SHA512)

Returns `{ uri: string, secret: string }`.

### `verifyToken(token, secret, options?)`

Checks a TOTP token against a secret without tracking prior successful uses. Use `verifyTokenOnce` for authentication.

- `token` (string): User-provided token with 6 to 8 digits
- `secret` (string): Canonical unpadded Base32 secret
- `options.window` (number): Time steps to check on either side of the current step (`0` to `2`; default `1`, meaning +/-30 seconds with the default period)
- `options.period` (number): Time step in seconds (default `30`)
- `options.algorithm` (string): Hash algorithm (default `SHA1`)
- `options.digits` (number): Expected token length (default `6`)
- `options.now` (number): Unix timestamp in seconds, useful for testing

Returns `boolean`.

### `verifyTokenOnce(token, secret, claimCounter, options?)`

Checks a token and passes its matched time-step counter to `claimCounter`. Returns `Promise<boolean>` and accepts the token only when the callback returns `true`. It rejects secrets shorter than 16 bytes.

The callback must **atomically** advance a durable, per-account `lastAcceptedCounter` only if the matched counter is greater than the stored value. Return `true` only when the update succeeds. A database conditional update or transaction can provide this guarantee across concurrent requests and server instances. An in-memory set cannot protect a multi-instance deployment or survive a restart.

```ts
import { verifyTokenOnce } from '@sourceregistry/node-totp';

const accepted = await verifyTokenOnce(token, user.totpSecret, counter =>
  db.claimTotpCounter(user.id, counter) // App-defined atomic conditional update
);
```

`options` has the same shape and defaults as `verifyToken`. Rate-limit attempts per account before calling either verifier.

### `generateToken(secret, counter, digits, algorithm)`

Generates a TOTP token.

- `secret` (Buffer): Decoded secret buffer
- `counter` (number): Time step counter
- `digits` (number): Token length (`6`, `7`, or `8`)
- `algorithm` (string): Hash algorithm (`SHA1`, `SHA256`, or `SHA512`)

Returns a zero-padded string token.

### `base32`

RFC 4648 Base32 helpers:

- `base32.encode(buffer: Buffer): string`
- `base32.decode(base32Str: string): Buffer`

The library accepts canonical unpadded Base32 secrets. Padded or non-canonical forms are normalized or rejected before use.

## Security Notes

- Token comparison uses `crypto.timingSafeEqual()`
- Supported algorithms are limited to `SHA1`, `SHA256`, and `SHA512`
- The HOTP/TOTP calculation supports `6`, `7`, or `8` digits; setup URIs support `6` or `8` as specified by the published key URI format
- Verification windows are limited to `0`, `1`, or `2` steps
- Period must be a positive integer
- New secrets must contain at least 16 bytes; generated secrets use algorithm-appropriate byte lengths by default
- Supplied secrets must also be randomly generated; length alone does not make a predictable secret secure
- The stateless `verifyToken` still accepts shorter existing secrets for migration; `verifyTokenOnce` requires at least 16 bytes
- Give every enrolled account a distinct random secret and protect secrets in storage
- Enforce attempt throttling across login sessions; the library has no account or attempt store
- Use `verifyTokenOnce` with a durable atomic counter claim to prevent code reuse
- Authenticator support for non-default algorithms and periods varies; test the chosen settings with the client apps you support

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

### Atomic replay claim

For a SQL-backed application, `db.claimTotpCounter(userId, counter)` can run a conditional update and return `true` only when one row changed:

```sql
UPDATE user_totp
SET last_accepted_counter = :counter
WHERE user_id = :user_id
  AND (last_accepted_counter IS NULL OR last_accepted_counter < :counter);
```

Keep the secret and `last_accepted_counter` per account. Enforce attempt throttling across sessions before calling `verifyTokenOnce`, and activate a new enrollment only after the user proves possession of the generated secret.
Reset the stored counter atomically when rotating that account's secret.

## License

Apache-2.0 © [A.P.A. Slaa](mailto:a.p.a.slaa@projectsource.nl)

---

**Note**: This library is designed for server-side Node.js applications. For browser usage, consider using a Web Crypto API compatible alternative.
