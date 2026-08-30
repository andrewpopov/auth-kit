---
kind: added
summary: New SingleUseTokenStore port + issueSingleUseToken/redeemSingleUseToken lifecycle for atomic, single-use reset/invite/email-change tokens, plus a conformance suite for adapter authors.
---

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
