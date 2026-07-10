# @andrewpopov/auth-kit

The authentication **primitives** that drifted across the custom-JWT backends
(bewks, cairn, savoro, towerpower, levelup, sano-os), outside
`express-security-kit`'s scope. Pure and stateless: password hashing and
single-use opaque tokens.

**Deliberately not here:** RBAC models, refresh-token stores, and 2FA flows —
those genuinely differ per app. Only the crypto primitives are shared.

Zero runtime dependencies. bcrypt is **injected**, so the native-`bcrypt` apps
keep their library and levelup keeps `bcryptjs` (their hashes are cross-verifiable).

## Install

```
npm install github:andrewpopov/auth-kit#v0.1.0
```

## Password hashing

```ts
import { createPasswordHasher } from '@andrewpopov/auth-kit';
import bcrypt from 'bcrypt';            // or: import bcrypt from 'bcryptjs'

const passwords = createPasswordHasher({ bcrypt, rounds: 12 });

const hash = await passwords.hash(plaintext);
const ok = await passwords.verify(plaintext, storedHash);

// Timing-safe login: compare against a valid hash on the account-absent branch
// so response timing never leaks whether an account exists.
await passwords.verify(attempt, user?.passwordHash ?? passwords.dummyHash());
```

`preHash: true` applies a SHA-256 pre-hash before bcrypt (defeats bcrypt's 72-byte
truncation — sano-os's approach). Adopt it only with **no existing hashes**, or via
a rehash-on-login migration: flipping it on plain-bcrypt hashes invalidates them.

## Single-use tokens (reset / invite / email-change)

```ts
import { generateOpaqueToken, hashOpaqueToken, verifyOpaqueToken } from '@andrewpopov/auth-kit';

// Issue: email the raw token, persist only its hash + an expiry.
const raw = generateOpaqueToken();
await store({ tokenHash: hashOpaqueToken(raw), expiresAt });

// Redeem: constant-time compare.
if (!row || row.expiresAt < now || !verifyOpaqueToken(raw, row.tokenHash)) reject();
```

`generateResetToken` / `hashResetToken` are aliases for the historical names.

## API

| Export | Purpose |
|---|---|
| `createPasswordHasher({ bcrypt, rounds?, preHash? })` | `→ { hash, verify, dummyHash, rounds }`. |
| `prehashPassword(pw)` | SHA-256 hex digest (the pre-hash primitive). |
| `generateOpaqueToken()` / `hashOpaqueToken(t)` | Random 256-bit token / its SHA-256 hash. |
| `verifyOpaqueToken(raw, storedHash)` | Constant-time verification. |
| `generateResetToken` / `hashResetToken` | Aliases of the opaque-token pair. |
| `DEFAULT_BCRYPT_ROUNDS` | `12`. |

## Standards

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).
