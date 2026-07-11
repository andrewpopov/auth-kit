# Changelog

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
