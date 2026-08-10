---
kind: fixed
summary: linkExternalIdentity surfaces a distinct not-eligible refusal (instead of the misleading identity-in-use), audits every explicit-link refusal reason including not-found, and never lets a broken audit sink break the returned outcome.
---

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
