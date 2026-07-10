# Changelog

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
