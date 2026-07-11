# Changelog

## 0.2.1

Fixes three defects found by an adversarial review of 0.2.0, before any
consumer adapter besides the in-progress (unmerged) smarthome one existed.

### BREAKING: `RefreshTokenStore.rotate()` signature and result shape changed

**Defect (HIGH): the benign-race branch could resurrect a token in a family
that had just been revoked (TOCTOU).** In 0.2.0, `store.rotate()` returned a
*snapshot* (`old` + `replacement`) and its transaction closed; the algorithm
then decided "benign race" from that snapshot and called `store.createSession`
as a **second, separate, unconditional** call with no re-check of family
state. Interleave: an attacker replays a stolen token and `rotate()` sees the
replacement still active; before the algorithm's follow-up insert runs, the
victim logs out (or an admin/password-reset revokes the family); the insert
then fires anyway, planting a live token in a family that was just killed —
defeating the logout. No consumer adapter could fix this: the two store calls
are the bug, not anything in between them.

**Fix:** `rotate()` now takes `(oldTokenHash, next, { graceMs, now })` and
performs the ENTIRE decision — including the benign-race-vs-reuse judgment
and its consequence (sibling insert, or family revoke) — in one atomic
call/transaction. `RotateStoreResult` drops `'already-revoked'` and gains
`'benign-race'` (sibling already inserted) and `'reuse'` (family already
revoked); there is no longer a decide-in-JS-then-act-as-a-second-call step for
either branch. This also closes the same class of round-trip on the `reuse`
path (family-kill is now inside the same atomic call, not a follow-up
`revokeFamily`), even though that particular round-trip was independently
safe (revocation is monotonic/idempotent — it can only kill more, never
resurrect).

**What an adapter author must change:** implement the full decision (grace
window + replacement-liveness check + benign-race insert OR family revoke)
inside your `rotate()` transaction, per the updated JSDoc on
`RefreshTokenStore.rotate` in `src/index.ts`. Then run the new adapter
conformance suite (below) against your real store.

### Defect (MEDIUM): the grace window was a reuse-detection bypass, defaulted ON

A token replayed within the old default 30s grace window was issued a fresh,
valid sibling and nothing was revoked or flagged — an attacker could launder
a stolen token into a legitimate-looking session that the victim never sees
flagged, then keep rotating the sibling forever (reuse never trips again
because the stolen token is never presented again). This is an honest
security/UX trade, not a coding bug — sano-os accepts it — but cairn
deliberately refuses it, so 0.2.0's "superset of cairn" framing was false:
cairn's strict family-kill is strictly stronger, and defaulting the window on
weakened it fleet-wide.

**Fix:** `rotateRefreshToken`'s `graceMs` now defaults to **`0`** (strict —
any replay of an already-rotated token is reuse). `DEFAULT_ROTATION_GRACE_MS`
(`30_000`) is still exported as a suggested value for callers who explicitly
opt in with `{ graceMs: DEFAULT_ROTATION_GRACE_MS }`. The grace-window trade
is now documented plainly (see README) instead of presented as a pure win.

### Defect (MEDIUM): the in-memory store's atomicity proved nothing about a real adapter

`createMemoryRefreshTokenStore().rotate` is `async` with no `await`, so it is
atomic "for free" under Node's run-to-completion semantics — the "N
concurrent `rotate()` → exactly one wins" test passed because JavaScript is
single-threaded, not because the algorithm/port contract is sound. It would
have passed identically against a store with no locking at all. A real
adopter (smarthome) confirmed the gap in practice: a read-then-write inside a
`$transaction` also passes on SQLite (which serializes writers) while the
same code is a classic lost update on Postgres at READ COMMITTED.

**Fix:** ships `runRefreshTokenStoreConformanceTests(makeStore, { describe, it,
expect })` from a new `@andrewpopov/auth-kit/conformance` subpath — any
adapter author runs it against their REAL store, asserting single-use under
genuine concurrency, family-kill, grace behavior (including the new `0`
default), expiry/revocation rejection, and the Defect-A regression. Passing
against the in-memory store proves nothing; a Postgres adapter needs
`SELECT ... FOR UPDATE` or an equivalent atomic CAS to pass this suite for
real. The suite takes `describe`/`it`/`expect` as INJECTED parameters rather
than importing a test runner itself — `vitest` ships ESM-only (no CJS
`require()` entry point), so a static import would have broken this package
for any consumer resolving it via CJS (caught by `verify:pack` against a real
vitest install, not assumed). `/conformance` therefore has zero runtime
dependencies too, same as the main entry.

**Also fixed (minor):** the in-memory store's expiry check used `Date.now()`
instead of the injected `now`, so an injected clock wasn't honored on that
branch — it now threads `now` throughout. The package description and the
top-of-file comment in `src/index.ts` no longer claim the whole package is
"pure and stateless" — password hashing and opaque tokens are; refresh-token
rotation is a stateful protocol over an injected store, and now says so.

## 0.2.0

Adds refresh-token session **rotation with reuse detection** — purely additive,
no existing export changed. This logic was hand-written five times across the
fleet (cairn, mizen, sano-os, smarthome, savoro), each getting the subtleties
differently; it was the highest-risk duplicated code we had. Composes the
superset of what those five got right:

- **Family-based rotation, single-use, atomic.** `createRefreshToken` /
  `rotateRefreshToken` / `revokeRefreshToken`. A refresh token IS an opaque
  token (`generateOpaqueToken` / `hashOpaqueToken`, reused, not reimplemented);
  rotation adds the state machine on top. Two concurrent rotations of the same
  token: exactly one wins.
- **Replay of an already-rotated token kills the whole family** (cairn's
  pattern) — not just the presented token, every token issued in that login
  session.
- **A grace window treats near-simultaneous rotation as a benign race, not
  theft** (sano-os's pattern, `DEFAULT_ROTATION_GRACE_MS = 30_000`,
  overridable, `0` to disable) — two browser tabs refreshing at nearly the same
  moment both come away with a working session instead of one nuking it.
- **`isEpochValid` for global invalidation** (mizen's `tokensValidFrom`
  pattern) — password reset / deactivate bumps a per-user epoch via
  `store.bumpEpoch`, invalidating every outstanding access token whose `epoch`
  claim predates it, independent of any single refresh token's lifecycle.
- **Storage is injected** via the `RefreshTokenStore` port (mirrors mizen's
  `AuthStore` shape — the proven port/adapter pattern), matching the existing
  injected-`bcrypt` idiom. auth-kit owns the algorithm; the five DB engines in
  use across the fleet (Prisma/pg/Drizzle, Postgres/SQLite) stay app-specific.
  `createMemoryRefreshTokenStore()` ships as a reference implementation and
  test double.
- Zero new runtime dependencies — still pure `crypto` only.

**Deliberately NOT added:** RBAC/role models, the JWT signing/verification
library (embed/verify the `epoch` claim yourself), cookie handling, and the
user model/CRUD. Those audited as genuinely per-app and out of scope for this
package, consistent with 0.1.0's boundary.

## 0.1.0

Initial release. Authentication *primitives* extracted from the custom-JWT
backends (bewks, cairn, savoro, towerpower, levelup, sano-os).

- Single-use opaque tokens: `generateOpaqueToken` / `hashOpaqueToken` /
  `verifyOpaqueToken` (constant-time). Backs password-reset, invite, and
  email-change flows; only the SHA-256 hash is stored. `generateResetToken` /
  `hashResetToken` aliases for the historical names.
- `createPasswordHasher({ bcrypt, rounds = 12, preHash = false })` → `hash` /
  `verify` / `dummyHash`. bcrypt is INJECTED (native `bcrypt` or `bcryptjs`), so
  no implementation is forced on any consumer. Optional SHA-256 `preHash`
  (sano-os best-of-breed, defeats bcrypt's 72-byte truncation). `dummyHash`
  gives a timing-safe absent-user compare.
- `prehashPassword` exported standalone.

Pure and stateless — RBAC models, refresh-token stores, and 2FA flows stay
app-specific by design.
