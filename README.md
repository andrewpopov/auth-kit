# @andrewpopov/auth-kit

The authentication **primitives and protocols** that drifted across the
custom-JWT backends (bewks, cairn, savoro, towerpower, levelup, sano-os),
outside `express-security-kit`'s scope: password hashing, single-use opaque
tokens, refresh-token session rotation, and provider-neutral OAuth identity
binding.

Password hashing and single-use opaque tokens are pure and stateless.
Refresh-token session rotation is **not** — it is a stateful protocol run
against an injected `RefreshTokenStore` port; auth-kit owns the algorithm,
never the storage engine.

**Deliberately not here:** RBAC models, the JWT signing/verification library,
cookie handling, and the user model/CRUD — those genuinely differ per app.
OAuth proof and account binding are shared because they must obey identical
security invariants, but each app still supplies its own account policy and
database adapter.

Zero runtime dependencies, including the `/conformance` subpath (adapter test
suite, see below) — bcrypt is **injected**, so the native-`bcrypt` apps keep
their library and levelup keeps `bcryptjs` (their hashes are
cross-verifiable), and `/conformance` likewise takes your `describe`/`it`/
`expect` as parameters instead of importing a test runner itself (`vitest`
ships ESM-only, with no CJS `require()` entry point at all, so importing it
internally would break this package for any consumer resolving via CJS).

## Install

```
npm install github:andrewpopov/auth-kit#v0.5.0
```

> **Upgrading from 0.2.0?** This is a **breaking release** for anyone who
> implemented the `RefreshTokenStore` port directly (no shipped adapter was
> merged yet, so this should affect nobody in the fleet today). See
> [`CHANGELOG.md`](./CHANGELOG.md) for what changed and why, and the
> "Implementing `RefreshTokenStore`" section below for the new contract.

> **Upgrading to 0.5.0?** PKG-25: the refresh-rotation **grace window now
> defaults to `DEFAULT_ROTATION_GRACE_MS` (30s)**, not `0`. If your deployment
> needs the old strict behavior (any replay of an already-rotated token is
> reuse, full stop), pass `{ graceMs: 0 }` explicitly to `rotateRefreshToken`.
> Read "The grace-window trade" below before relying on either default.

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

Issuing a random token is the easy half; the "single-use" property — a
redeemed or invalidated token can never redeem again, even under concurrent
requests — is a storage problem, not a crypto one. That property is now a
first-class port, `SingleUseTokenStore`, run through `issueSingleUseToken` /
`redeemSingleUseToken`, the same shape as `RefreshTokenStore.rotate()`.
auth-kit owns the algorithm; you implement the store against Prisma/pg/
Drizzle/whatever. A `createMemorySingleUseTokenStore()` reference
implementation ships for tests.

```ts
import {
  issueSingleUseToken,
  redeemSingleUseToken,
  type SingleUseTokenStore,
} from '@andrewpopov/auth-kit';

const store: SingleUseTokenStore = /* your Prisma/pg/Drizzle-backed implementation */;
const TTL_MS = 15 * 60 * 1000; // 15 minutes

// Issue: email the raw token as a URL param, persist only its hash + expiry.
const { rawToken, expiresAt } = await issueSingleUseToken(store, {
  purpose: 'password-reset',
  subjectId: user.id,
  ttlMs: TTL_MS,
});
// -> mail a link containing rawToken; never persist it yourself.

// Redeem: atomic, single-use, purpose-scoped.
const result = await redeemSingleUseToken(store, presentedRawToken, { purpose: 'password-reset' });
if (result.outcome === 'invalid') throw new Error('unknown token or wrong purpose');
if (result.outcome === 'already-consumed') throw new Error('this link was already used');
if (result.outcome === 'expired') throw new Error('this link expired — request a new one');
// result.outcome === 'redeemed' -> result.record.subjectId is who to act on.
```

`store.consume()` is the one method that MUST be atomic — a single
transaction / conditional `UPDATE`, not a select followed by an update. Two
concurrent redeems of the same token must not both succeed. Run
`runSingleUseTokenStoreConformanceTests` (below, under "Testing a real
adapter") against your real store before trusting it; passing it against
`createMemorySingleUseTokenStore()` proves nothing about a real adapter's
atomicity, for the same reason the refresh-token suite doesn't.

**Replace-on-issue (killing an old reset link when mailing a new one) is
NOT atomic.** There is no `issueSingleUseToken(..., { invalidateExisting: true })`
option, and none is planned — it would need a third atomic op
(`issueReplacingOutstanding`) for what is really host policy. A host that
wants "the newest link is the only valid one" calls `invalidateAllFor` then
`issueSingleUseToken` itself, as two separate calls:

```ts
await store.invalidateAllFor(user.id, 'password-reset');
const { rawToken } = await issueSingleUseToken(store, { purpose: 'password-reset', subjectId: user.id, ttlMs: TTL_MS });
```

Because these are two calls, not one transaction, a concurrent issue can
leave more than one live token outstanding, and if the `issue` call fails
after the `invalidateAllFor` succeeded, the old token is dead with no
replacement minted. auth-kit does not paper over this — own the non-atomicity
explicitly, or accept that a brief overlap window is possible.

The raw primitives remain exported for hosts doing their own thing outside
this lifecycle:

```ts
import { generateOpaqueToken, hashOpaqueToken, verifyOpaqueToken } from '@andrewpopov/auth-kit';

const raw = generateOpaqueToken();
const hash = hashOpaqueToken(raw);
verifyOpaqueToken(raw, hash); // constant-time compare
```

`generateResetToken` / `hashResetToken` are aliases for the historical names.

## OAuth and external identity binding

OAuth and user management are separate layers:

1. `auth-kit` OAuth helpers prove an external identity and return
   `{ issuer, subject, verified claims }`.
2. The identity engine decides whether the identity is returning, explicitly
   links to the current local account, safely claims an unverified placeholder,
   provisions a new account, conflicts, or is refused.
3. The app continues to own user rows, roles, memberships, invitations,
   deactivation, session cookies/JWTs, and UI.

**Email is a verified claim, never the durable identity key.** Returning users
are resolved by `(issuer, subject)`. An unauthenticated OAuth callback never
adopts a credentialed or independently verified local account just because its
email matches. Existing users link Google only while authenticated in the app,
through a same-browser OAuth ceremony.

### OAuth proof

```ts
import {
  createOAuthState,
  createPkcePair,
  createGoogleAuthorizationUrl,
  requireSameBrowserOAuthState,
  exchangeGoogleAuthorizationCode,
} from '@andrewpopov/auth-kit';

const state = createOAuthState({ secret: process.env.OAUTH_STATE_SECRET!, intent: { purpose: 'link', accountId } });
// Store this exact state in an HttpOnly, SameSite=Lax, callback-scoped cookie.
const pkce = createPkcePair();
const url = createGoogleAuthorizationUrl({ clientId, redirectUri, state, pkce });

// In the callback: reject unless query state exactly matches the initiating
// browser's cookie, then clear the cookie before exchanging the code.
const intent = requireSameBrowserOAuthState(query.state, requestCookie, process.env.OAUTH_STATE_SECRET!);
if (!intent) throw new Error('OAuth request is invalid or expired');

const identity = await exchangeGoogleAuthorizationCode({
  code: query.code,
  clientId,
  clientSecret,
  redirectUri,
  codeVerifier: pkceVerifier,
  verifier: {
    // Use google-auth-library, jose, Passport, or a framework-provided
    // verifier. It MUST cryptographically verify the ID token signature.
    verify: async (idToken, audience) => verifiedGoogleClaims(idToken, audience),
  },
});
```

`exchangeGoogleAuthorizationCode` does not query an app database. Its injected
verifier must cryptographically validate the ID token; auth-kit then requires
Google's issuer, audience, non-empty stable subject, and normalized claims.

### Account binding

```ts
import { resolveExternalIdentity, linkExternalIdentity } from '@andrewpopov/auth-kit';

// Unauthenticated login callback: returning subject, safe placeholder claim,
// deliberate provisioning, or a typed refusal. Never email-auto-links a real
// account.
const login = await resolveExternalIdentity(identityStore, accountPolicy, identity);

// Authenticated settings flow only: current app session plus the same-browser
// OAuth proof above. Matching verified email is required by default.
const linked = await linkExternalIdentity(identityStore, accountPolicy, currentAccountId, identity);
```

`ExternalIdentityStore` performs atomic binding/claim operations and enforces a
unique `(issuer, subject)` binding. `AccountIdentityPolicy` is where each app
expresses registration, invitation, tenancy, allowlist, and placeholder rules.
There is deliberately no `allowDangerousEmailAccountLinking` switch.

Run both conformance suites against a real database adapter:

```ts
import { runExternalIdentityStoreConformanceTests } from '@andrewpopov/auth-kit/conformance';

runExternalIdentityStoreConformanceTests(makeStore, prepareFixture, { describe, it, expect });
```

## Refresh-token session rotation (with reuse detection)

Hand-written five times across the fleet, each getting the subtleties
differently. Composes: cairn's family-kill-on-replay, mizen's
`tokensValidFrom` epoch for global invalidation, and sano-os's benign-race
grace window — which now ships **on by default**, at 30s (see "The
grace-window trade" below — it is not a pure win, and you can opt back into
cairn's strict posture with `graceMs: 0`).

Storage is **injected** via `RefreshTokenStore` — implement it against
Prisma/pg/Drizzle/whatever; auth-kit owns only the rotation algorithm. A
`createMemoryRefreshTokenStore()` reference implementation ships for tests —
see "Testing a real adapter" below before trusting a store you write against
it.

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
`graceMs` **defaults to `DEFAULT_ROTATION_GRACE_MS` (30s, sano-os's value)**
as of 0.5.0 (PKG-25). Pass `{ graceMs: 0 }` explicitly to restore the
original strict behavior (cairn/mizen's: any replay of an already-rotated
token is reuse, full stop) — read the trade below either way.

### The grace-window trade (read before you rely on the default)

A grace window is **not a pure win** — it is a real reuse-detection bypass,
traded for UX. With the default `graceMs` (or any non-zero value):

> An attacker who replays a stolen refresh token **within `graceMs` of its
> legitimate rotation** is issued a fresh, valid **sibling** token in the same
> family, and **nothing is revoked or flagged**. They then keep rotating
> their own sibling on the live branch forever; reuse never trips again,
> because the stolen token is never presented again. **The theft is laundered
> into a legitimate-looking session, and the victim sees nothing.**

sano-os accepts this trade deliberately (two browser tabs refreshing near-
simultaneously shouldn't both get logged out) — and as of PKG-25 that is also
auth-kit's own default: a refresh dedup that only spans one tab, paired with
a strict grace window, turned an ordinary sibling-tab race into "logged out
of every tab." The cost is real: for up to 30 seconds after a legitimate
rotation, an attacker holding the just-rotated token can still mint a valid
sibling session with no revocation or signal. This default trades that
bounded replay interval for multi-tab resilience. **cairn
still runs strict** — its `auth.service.ts` has a comment reading *"we
intentionally do NOT add a grace window"* — and deployments with that
requirement should pass `{ graceMs: 0 }` explicitly rather than rely on the
package default. auth-kit is **not** a superset of cairn's behavior when a
non-zero `graceMs` is in effect; it is a deliberately weaker default that
ships because it matches the majority of the fleet's browser-based bearer
clients better than strict-by-default did.

**Pair this with a client-side defense for browser bearer-auth clients.**
The grace window is the server-side half of the fix; if your client is
`@andrewpopov/fetch-client-kit`'s `bearerAuth`, also enable its
`crossTabRefresh` option so sibling tabs coordinate a single in-flight
refresh instead of each firing their own — the two controls together (client
dedup first, server grace window as the backstop) close the footgun described
in PKG-25 far better than either alone.

## Implementing `RefreshTokenStore`

`rotate()` is the one method that MUST be atomic — and as of 0.2.1 it is the
**entire** rotation decision, not just the single-use compare-and-swap. Given
`(oldTokenHash, next, { graceMs, now })`, in ONE transaction / row lock:

1. No row for `oldTokenHash` → `{ status: 'not-found' }`.
2. Row not revoked, not expired → mark it revoked (`revokedAt = now`,
   `replacedById = next.id`), insert `next` → `{ status: 'rotated', session }`.
   Two concurrent callers racing the same `oldTokenHash` must NOT both
   observe `'rotated'`.
3. Row not revoked, but past `expiresAt` → `{ status: 'expired', old }`.
4. Row already revoked: resolve its replacement via `replacedById` (fresh, in
   THIS transaction), and using `now`/`graceMs`, decide:
   - within grace AND replacement still active (not revoked, not expired) →
     insert `next` as a **new sibling** in the same family →
     `{ status: 'benign-race', session }`.
   - otherwise → revoke every still-active session in the family (same effect
     as `revokeFamily`) → `{ status: 'reuse', userId, familyId }`.

The check in step 4 and its action (insert or revoke) **must** happen without
releasing the lock/leaving the transaction in between — see the full JSDoc on
`RefreshTokenStore.rotate` in `src/index.ts` for the reasoning (this is the
fix for the 0.2.0 TOCTOU, see CHANGELOG).

## Testing a real adapter

**Passing the in-memory store's tests proves nothing about a real adapter's
atomicity.** `createMemoryRefreshTokenStore().rotate` is atomic "for free"
because JavaScript is single-threaded and its `rotate()` has no internal
`await` — it would pass identically against a store with no locking at all. A
real database can, and on Postgres at READ COMMITTED will, let two concurrent
`rotate()` calls on the same token both "win" (a classic lost update) unless
the transaction uses `SELECT ... FOR UPDATE` or an equivalent atomic
compare-and-swap.

Run the shipped conformance suite against your REAL store before trusting it,
from inside your own vitest (or Jest) test file — pass your own
`describe`/`it`/`expect` in, the suite doesn't import a test runner itself:

```ts
import { describe, it, expect } from 'vitest';
import { runRefreshTokenStoreConformanceTests } from '@andrewpopov/auth-kit/conformance';
import { createMyPostgresStore } from '../src/postgres-store';

runRefreshTokenStoreConformanceTests(() => createMyPostgresStore(testDb), { describe, it, expect });
```

It asserts (against N genuinely concurrent calls, not just sequential ones):
single-use under concurrency, family-kill on reuse, the grace-window/benign-
race behavior (including both the `DEFAULT_ROTATION_GRACE_MS` default and the
`graceMs: 0` strict opt-out), expiry/revocation rejection, and the Defect-A
regression (no live token ever survives in a revoked family).

The same is true for `SingleUseTokenStore`: `createMemorySingleUseTokenStore().consume`
is atomic "for free" for the same single-threaded, no-internal-`await` reason.
Run `runSingleUseTokenStoreConformanceTests` against your real store before
trusting it:

```ts
import { describe, it, expect } from 'vitest';
import { runSingleUseTokenStoreConformanceTests } from '@andrewpopov/auth-kit/conformance';
import { createMyPostgresStore } from '../src/postgres-store';

runSingleUseTokenStoreConformanceTests(() => createMyPostgresStore(testDb), { describe, it, expect });
```

It asserts: the happy path and sequential replay, single-use under N
genuinely concurrent `consume()` calls on the same token (asserting both the
one winner AND the N-1 losers report `already-consumed`, not just counting
winners), `tokenHash` uniqueness under N genuinely concurrent `issue()` calls
on the same hash (exactly one succeeds — the sequential duplicate-`issue`
case alone can't catch a non-atomic check-then-insert adapter, since nothing
races it), that `consume()` reports `already-consumed` once a prior
`invalidateAllFor()` call has fully resolved (deterministic, no ordering
ambiguity), expiry rejecting a token under sequential calls with a fixed
`now` (including the `now === expiresAt` boundary), purpose isolation, and
`invalidateAllFor`'s no-delete/idempotency contract.

Two things this suite does **not** prove, so read past the green checkmark:
the `consume()`-vs-`invalidateAllFor()` race case beyond the deterministic
check above is a SMOKE TEST that the two calls don't corrupt each other under
real concurrent I/O, not a linearization proof — this port exposes no way to
observe which of the two committed first, so a consume() that reads before
and writes after invalidateAllFor() commits (the exact violation the
contract forbids) is indistinguishable here from a legitimate win; proving
that ordering would need an adapter synchronization hook this port doesn't
expose. And the expiry case above only ever calls `consume()` sequentially
with a fixed `now`, so it cannot establish that expiry is decided *inside*
the adapter's transaction (an adapter that checks expiry outside its
transaction still passes) — the contract in `SingleUseTokenStore.consume`'s
doc comment still requires in-transaction expiry, this suite just doesn't
verify it.

`options.concurrency` (default 20) and `options.raceRepeats` (default 5) are
validated, not just defaulted — passing a non-integer, a non-finite value
(`NaN`, `Infinity`), `concurrency < 2`, or `raceRepeats < 1` throws, since a
race that can't lose isn't testing anything.

## API

| Export | Purpose |
|---|---|
| `createPasswordHasher({ bcrypt, rounds?, preHash? })` | `→ { hash, verify, dummyHash, rounds }`. |
| `prehashPassword(pw)` | SHA-256 hex digest (the pre-hash primitive). |
| `generateOpaqueToken()` / `hashOpaqueToken(t)` | Random 256-bit token / its SHA-256 hash. |
| `verifyOpaqueToken(raw, storedHash)` | Constant-time verification. |
| `generateResetToken` / `hashResetToken` | Aliases of the opaque-token pair. |
| `SingleUseTokenStore` | The storage port to implement (`issue`, `consume`, `invalidateAllFor`). `consume` MUST be atomic. |
| `issueSingleUseToken(store, { purpose, subjectId, ttlMs, now? })` | Mints a token, persists only its hash. `→ { rawToken, id, expiresAt }`. |
| `redeemSingleUseToken(store, rawToken, { purpose, now? })` | Atomic, single-use, purpose-scoped redeem. `→ { outcome: 'redeemed'\|'already-consumed'\|'expired'\|'invalid', ... }`. |
| `createMemorySingleUseTokenStore()` | In-memory `SingleUseTokenStore` — test double, not for production. |
| `runSingleUseTokenStoreConformanceTests(makeStore, { describe, it, expect }, opts?)` | From `@andrewpopov/auth-kit/conformance`. Adapter conformance suite — run against a REAL store before trusting it. |
| `DEFAULT_BCRYPT_ROUNDS` | `12`. |
| `RefreshTokenStore` | The storage port to implement (`createSession`, `findByHash`, `rotate`, `revokeFamily`, `revokeAllForUser`, `getEpoch`, `bumpEpoch`). |
| `createRefreshToken(store, userId, ttlMs, opts?)` | Issue a token, starting a new family. |
| `rotateRefreshToken(store, rawToken, ttlMs, opts?)` | Single-use atomic rotation + reuse detection. `→ { outcome: 'rotated'\|'reuse'\|'invalid', ... }`. |
| `revokeRefreshToken(store, rawToken)` | Logout: revoke the token's whole family. |
| `isEpochValid(tokenEpochMs, currentEpoch)` | Check an access token's `epoch` claim against the user's current epoch. |
| `DEFAULT_ROTATION_GRACE_MS` | `30_000` — the default for `rotateRefreshToken`'s `graceMs` as of 0.5.0 (PKG-25). Pass `graceMs: 0` for the old strict behavior. |
| `createMemoryRefreshTokenStore()` | In-memory `RefreshTokenStore` — test double, not for production. |
| `runRefreshTokenStoreConformanceTests(makeStore, { describe, it, expect }, opts?)` | From `@andrewpopov/auth-kit/conformance`. Adapter conformance suite — run against a REAL store before trusting it. Test-runner primitives are injected, not imported. |
| `createOAuthState` / `verifyOAuthState` / `requireSameBrowserOAuthState` | Signed short-lived OAuth intent and same-browser callback binding. |
| `createPkcePair` / `createGoogleAuthorizationUrl` | PKCE S256 and Google authorization URL construction. |
| `exchangeGoogleAuthorizationCode` | Code exchange plus injected cryptographic ID-token verifier, producing `ExternalIdentity`. |
| `resolveExternalIdentity` / `linkExternalIdentity` | Provider-neutral login resolution and authenticated explicit linking. |
| `runExternalIdentityStoreConformanceTests` | Real-adapter identity binding, placeholder, and concurrency conformance suite. |

## Standards

## Policy validation

`createPasswordHasher` accepts bcrypt rounds only in `4..31`. Refresh-token
TTLs and OAuth state TTLs must be positive integer milliseconds; `graceMs` must
be a non-negative integer. Invalid policy values throw `AuthPolicyError` before
credentials or state are issued.

## Verify locally

```bash
npm ci
npm run verify
npm audit --omit=dev --audit-level=high
```

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).

## Project policies

See [Contributing](./CONTRIBUTING.md), [Support](./SUPPORT.md), and the
[Security Policy](./SECURITY.md). This package is licensed under [MIT](./LICENSE).
