---
kind: security
summary: createPasswordHasher's dummyHash() now hashes a random internal plaintext, so the documented guarantee that no CALLER-supplied password matches it is actually true.
---

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
