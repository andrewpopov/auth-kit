---
kind: security
summary: Refuse external-identity placeholder claims unless the issuer is authoritative for the address
---

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
