---
kind: breaking
summary: ExternalIdentity.emailVerified is replaced by emailAuthority
---

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
