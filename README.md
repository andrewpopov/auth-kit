# @andrewpopov/auth-kit

The authentication **primitives** that drifted across the custom-JWT backends
(bewks, cairn, savoro, towerpower, levelup, sano-os), outside
`express-security-kit`'s scope: password hashing, single-use opaque tokens, and
refresh-token session rotation with reuse detection.

**Deliberately not here:** RBAC models, the JWT signing/verification library,
cookie handling, and the user model/CRUD — those genuinely differ per app.
Storage for refresh sessions is **injected** via a port (see below), same idiom
as the injected `bcrypt`.

Zero runtime dependencies. bcrypt is **injected**, so the native-`bcrypt` apps
keep their library and levelup keeps `bcryptjs` (their hashes are cross-verifiable).

## Install

```
npm install github:andrewpopov/auth-kit#v0.2.0
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

## Refresh-token session rotation (with reuse detection)

Hand-written five times across the fleet, each getting the subtleties
differently. Composes: cairn's family-kill-on-replay, mizen's `tokensValidFrom`
epoch for global invalidation, and sano-os's benign-race grace window (two
browser tabs refreshing near-simultaneously must not nuke the session).

Storage is **injected** via `RefreshTokenStore` — implement it against
Prisma/pg/Drizzle/whatever; auth-kit owns only the rotation algorithm. A
`createMemoryRefreshTokenStore()` reference implementation ships for tests.

```ts
import {
  createRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  isEpochValid,
  type RefreshTokenStore,
} from '@andrewpopov/auth-kit';

const store: RefreshTokenStore = /* your Prisma/pg/Drizzle-backed implementation */;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Login: start a new family.
const { rawToken, familyId, expiresAt } = await createRefreshToken(store, user.id, TTL_MS);
// -> set rawToken as an httpOnly cookie; sign an access JWT with { sub: user.id, epoch: (await store.getEpoch(user.id))?.getTime() }.

// Refresh: single-use, atomic, family-based reuse detection.
const result = await rotateRefreshToken(store, presentedRawToken, TTL_MS);
if (result.outcome === 'invalid') throw new Error('unauthenticated');
if (result.outcome === 'reuse') throw new Error('session revoked — reuse detected');
// result.outcome === 'rotated' -> result.rawToken is the new cookie value.

// Logout (this session only): kills the whole family.
await revokeRefreshToken(store, presentedRawToken);

// Logout everywhere / password reset / deactivate:
await store.revokeAllForUser(user.id);
const newEpoch = await store.bumpEpoch(user.id); // invalidates outstanding access tokens

// Verifying an access token's `epoch` claim against the current epoch:
if (!isEpochValid(claims.epoch, await store.getEpoch(user.id))) throw new Error('session invalidated');
```

`rotateRefreshToken`'s third argument accepts `{ graceMs?, now? }` —
`graceMs` defaults to `DEFAULT_ROTATION_GRACE_MS` (30s, sano-os's value);
pass `0` to disable the grace window (cairn/mizen's strict behavior — any
double-submit is treated as reuse).

## API

| Export | Purpose |
|---|---|
| `createPasswordHasher({ bcrypt, rounds?, preHash? })` | `→ { hash, verify, dummyHash, rounds }`. |
| `prehashPassword(pw)` | SHA-256 hex digest (the pre-hash primitive). |
| `generateOpaqueToken()` / `hashOpaqueToken(t)` | Random 256-bit token / its SHA-256 hash. |
| `verifyOpaqueToken(raw, storedHash)` | Constant-time verification. |
| `generateResetToken` / `hashResetToken` | Aliases of the opaque-token pair. |
| `DEFAULT_BCRYPT_ROUNDS` | `12`. |
| `RefreshTokenStore` | The storage port to implement (`createSession`, `findByHash`, `rotate`, `revokeFamily`, `revokeAllForUser`, `getEpoch`, `bumpEpoch`). |
| `createRefreshToken(store, userId, ttlMs, opts?)` | Issue a token, starting a new family. |
| `rotateRefreshToken(store, rawToken, ttlMs, opts?)` | Single-use atomic rotation + reuse detection. `→ { outcome: 'rotated'\|'reuse'\|'invalid', ... }`. |
| `revokeRefreshToken(store, rawToken)` | Logout: revoke the token's whole family. |
| `isEpochValid(tokenEpochMs, currentEpoch)` | Check an access token's `epoch` claim against the user's current epoch. |
| `DEFAULT_ROTATION_GRACE_MS` | `30_000`. |
| `createMemoryRefreshTokenStore()` | In-memory `RefreshTokenStore` — test double, not for production. |

## Standards

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).
