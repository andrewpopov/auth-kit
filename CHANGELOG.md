# Changelog

## 0.7.0

- runExternalIdentityStoreConformanceTests adds a concurrent claimPlaceholder race, catching non-atomic placeholder-claim adapters the suite previously missed.
  `runExternalIdentityStoreConformanceTests` already promised (in its own doc
  comment) that `bindExternalIdentity` and `claimPlaceholder` must decide and
  act atomically, but only `bindExternalIdentity` had a genuine concurrency
  canary — `claimPlaceholder` was exercised only once, sequentially, so a
  non-atomic adapter could pass the suite while violating the stated contract.
  The suite now also races N concurrent `claimPlaceholder` calls against ONE
  placeholder, repeated over fresh placeholders (a new `raceRepeats` option,
  default 5), asserting exactly one claim wins each round. Adapter authors
  should re-run the suite against their real store.
  
  Two refinements from the first pass: the race deliberately contends for a
  SINGLE placeholder per round rather than several placeholders sharing one
  normalized email — the latter spuriously fails against an otherwise-conforming
  adapter that enforces email uniqueness. And the race is now documented as
  PROBABILISTIC rather than implied-certain: `Promise.all` gives genuine
  concurrency but no barrier between an adapter's internal read and write
  phases, so a truly non-atomic adapter could still pass any single round by
  scheduling luck — repeating over fresh state makes that unlikely across every
  round, not impossible.
- New SingleUseTokenStore port + issueSingleUseToken/redeemSingleUseToken lifecycle for atomic, single-use reset/invite/email-change tokens, plus a conformance suite for adapter authors.
  Single-use opaque tokens (password reset, invite, email-change) previously
  had no storage seam: `generateOpaqueToken`/`hashOpaqueToken`/`verifyOpaqueToken`
  were pure and stateless, so "single-use" — the actual security property these
  tokens exist to provide — was entirely the host's problem, and the README
  documented redemption as a bare hash compare with no consume/retire step at
  all. A new `SingleUseTokenStore` port closes that gap, mirroring
  `RefreshTokenStore.rotate()`: `store.consume()` is a single atomic
  decide-and-act operation that checks purpose, consumed state, and expiry
  inside one transaction and reports `consumed` / `already-consumed` /
  `expired` / `purpose-mismatch` / `not-found`, so two concurrent redeems of
  the same token cannot both succeed. `issueSingleUseToken` and
  `redeemSingleUseToken` are the algorithm layer against that port, and
  `createMemorySingleUseTokenStore()` ships a test double. A
  `runSingleUseTokenStoreConformanceTests` suite (from
  `@andrewpopov/auth-kit/conformance`) is included for adapter authors to run
  against their real store — passing it against the in-memory store proves
  nothing about a real adapter's atomicity, same caveat as the refresh-token
  suite.
  
  Replace-on-issue (invalidating an old reset/invite link when mailing a new
  one) is deliberately **not** an atomic primitive: it's the host calling
  `invalidateAllFor` then `issueSingleUseToken`, two separate calls, so a
  concurrent issue can leave more than one live token outstanding and a failed
  `issue` after a successful `invalidateAllFor` leaves no replacement. Hosts
  that need that behavior own the non-atomicity explicitly; the port doesn't
  claim a guarantee it can't keep.
- the aggregate verification gate now rejects stale committed build output
  `npm run verify` now invokes the existing `verify:dist-fresh` guard before
  packing the package.
- linkExternalIdentity surfaces a distinct not-eligible refusal (instead of the misleading identity-in-use), audits every explicit-link refusal reason including not-found, and never lets a broken audit sink break the returned outcome.
  `ExplicitLinkResolution` gains a `not-eligible` outcome, and `linkExternalIdentity`
  now maps a store's `not-eligible` `BindResult` to it directly instead of
  collapsing it into `identity-in-use` — a caller no longer gets told "this
  identity belongs to someone else" when the real reason is "this account isn't
  eligible to link." Every refusal branch (`unverified-email`, `identity-in-use`,
  `account-already-linked`, `not-eligible`, and `not-found` — an attempt to link
  against an account id that does not resolve, audited against the ATTEMPTED
  id since that mismatch is itself the interesting signal) now records an
  `EXTERNAL_IDENTITY_REFUSED` audit event through one shared refusal path, so
  security-relevant explicit-link refusals are no longer silently invisible to
  audit consumers.
  
  The shared audit path also isolates a throwing/rejecting `IdentityAuditSink`:
  previously, once refusals started routing through it, a broken sink turned an
  otherwise-correct typed outcome into a rejected promise. A sink failure is now
  caught and surfaced via `console.warn` (never silently dropped) instead of
  propagating — the same isolate-then-surface guarantee express-security-kit's
  `AuditBuffer` makes for its own sink.
- createPasswordHasher's dummyHash() now hashes a random internal plaintext, so the documented guarantee that no CALLER-supplied password matches it is actually true.
  `dummyHash()` previously hashed the fixed, public literal
  `'absent-user-timing-padding'` — since that string lives in the package's own
  source, it verified successfully against the returned hash, contradicting the
  documented guarantee that "no real password matches" it. `dummyHash()` now
  hashes a random 256-bit plaintext generated internally per hasher, never
  retained or exposed, so the guarantee is now genuinely true. The value is
  still computed once (via `hashSync`) and cached, so cost and timing
  characteristics are unchanged, and it stays stable across repeated calls on
  the same hasher.
  
  The doc comment is now precise rather than absolute: the guarantee covers
  passwords passed to `hash`/`verify`. `bcrypt` is injected, so a host that
  wraps its own bcrypt implementation can observe the plaintext handed to
  `hashSync` here, same as it can for every real hash/verify call — that's not
  a new capability, since such a host already controls all password hashing in
  the process.

## 0.6.1

- Release tooling bumped to release-kit v0.3.1
  Development-only: `@andrewpopov/release-kit` moves from v0.2.0 to v0.3.1. No
  runtime or API change — the published `dist/` is unaffected. v0.2.0 predated
  kind-derived version bumps, which is why cutting 0.6.0 (a `breaking` fragment)
  first produced a patch bump and needed an explicit `--version`. v0.3.1 derives
  the level from fragment kinds, refuses to auto-version an implicit major/minor
  when the strategy has not declared support, and fixes `release:hygiene` so a
  branch that cuts a release can pass it.

## 0.6.0

- ExternalIdentity.emailVerified is replaced by emailAuthority
  `ExternalIdentity.emailVerified: boolean` is replaced by
  `emailAuthority: 'none' | 'asserted' | 'hosted'`, because a boolean cannot express the
  difference between "the issuer says this address is verified" and "the issuer is
  authoritative for this address right now". Adapters built through
  `externalIdentityFromVerifiedGoogleClaims` inherit the new value for free — pass the ID
  token's `hd` claim through, which `GoogleIdTokenClaims` now accepts. Adapters that construct
  `ExternalIdentity` by hand must supply `emailAuthority` themselves; the exported
  `googleEmailAuthority(normalizedEmail, emailVerified, hd)` implements Google's documented
  rule (`@gmail.com`/`@googlemail.com`, or `hd` present). `AccountIdentityRecord.emailVerified`
  — the application's own local verification state — is a different fact and is unchanged.
  Apps that gated `mayClaimCredentialedPlaceholder` on the issuer should drop that check: the
  engine now enforces authority itself, and issuer-granular gating was never sufficient.
- Manage releases with release-kit (fragment-based CHANGELOG + version bump)
  Releases are now driven by release-kit: describe each change as a fragment under `.changes/unreleased/` and run `npm run release:cut` to compile them into a new CHANGELOG section, bump the version, and archive the fragments.
- Refuse external-identity placeholder claims unless the issuer is authoritative for the address
  `resolveExternalIdentity` permitted a placeholder claim — which nulls the account's password
  and revokes its sessions — whenever the provider asserted a verified email. That assertion
  proves control of the external account, not present control of the mailbox: a Google account
  created against a third-party address keeps `email_verified: true` after the address changes
  hands, so a former owner could claim the rightful owner's placeholder. The engine now refuses
  any claim unless `emailAuthority` is `'hosted'`, checked before either policy hook runs, and
  such identities resolve to `account-exists` instead. An unrecognized `emailAuthority` — from
  a JavaScript consumer, a deserialized object, or a stale compiled adapter — fails closed and
  yields `unverified-email` rather than being treated as verified. Note the bar cannot distinguish a
  transferred *domain* — re-registering a lapsed domain confers genuine present authority over
  its addresses, and an app-sent email challenge is no stronger there; only a factor bound to
  the person is.

## 0.5.0

- **Behavior change (PKG-25):** `rotateRefreshToken`'s `graceMs` now
  **defaults to `DEFAULT_ROTATION_GRACE_MS` (30s)** instead of `0`. Root
  cause: consumers combining per-tab-only refresh dedup (no client-side
  cross-tab coordination) with the old strict-by-default grace window would
  have an ordinary sibling-tab refresh race misclassified as token reuse,
  triggering family-wide revocation and logging the user out of every open
  tab. The 30s window tolerates that benign race while still treating a
  replay presented after the window — or any replay when `graceMs: 0` is
  passed explicitly — as genuine reuse, revoking the family as before.
  Deployments that require the original strict behavior (e.g. cairn) must now
  pass `{ graceMs: 0 }` explicitly; see the README's "Upgrading to 0.5.0" and
  "The grace-window trade" sections, including the recommended pairing with
  `@andrewpopov/fetch-client-kit`'s `crossTabRefresh` for browser bearer-auth
  clients.

## 0.4.0

- Add an opt-in `AccountIdentityPolicy.mayClaimCredentialedPlaceholder` method
  that permits `resolveExternalIdentity` to claim a placeholder account that
  HAS first-party credentials (a password). Default (method omitted) behavior
  is byte-for-byte unchanged: the engine still refuses to claim a credentialed
  placeholder. Only implement this if unverified accounts in your app are
  inert (cannot log in, hold no sessions) — otherwise the opt-in would hand
  over a live account. `!emailVerified`, matching email, and
  `mayClaimPlaceholder` remain mandatory; the opt-in relaxes only the
  first-party-credentials term.

## 0.3.1

- Add public contribution, support, and private vulnerability-reporting policies.
- Reject invalid bcrypt rounds, refresh-token TTLs, OAuth state TTLs, and
  rotation grace windows with `AuthPolicyError` rather than creating expired or
  otherwise nonsensical credentials.
- Add `npm run verify` for the local release gate.
- Upgrade the Vitest development toolchain to a version with no known advisories.

## 0.3.0

Adds provider-neutral OAuth/OIDC external identity binding.

- **Proof layer:** signed short-lived state, same-browser correlation helper,
  PKCE S256, Google authorization URL construction, authorization-code
  exchange, and an injected cryptographic ID-token verifier. The package
  requires Google's issuer, audience, stable subject, and verified-claim shape
  before producing an `ExternalIdentity`.
- **Binding layer:** returning login by `(issuer, subject)`, authenticated
  explicit linking, narrow app-policy-approved placeholder claims, deliberate
  provisioning, typed conflicts/refusals, and an injected audit sink.
- **No email adoption:** an unauthenticated OAuth callback cannot auto-link a
  credentialed or independently verified local account by email. This closes
  the pre-hijacking/account-takeover class that diverged across consumers.
- **Conformance:** `runExternalIdentityStoreConformanceTests` exercises real
  adapter behavior for subject uniqueness, no credentialed-email adoption,
  placeholder claiming, and concurrent linking.

This is additive at the export level but deliberately requires an adapter and
policy migration before a consumer replaces its existing OAuth flow.

## 0.2.2

Fix — expose `./package.json` in the `exports` map. Without it,
`require('@andrewpopov/auth-kit/package.json')` threw
`ERR_PACKAGE_PATH_NOT_EXPORTED` — which broke the standards' own documented way of
verifying an INSTALLED version, the guard against the `github:` re-resolve trap.

No runtime change.

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
