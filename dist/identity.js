"use strict";
/**
 * Provider-neutral external identity binding.
 *
 * OAuth proves an identity; it does not authorize a mutation of an app's user
 * model. This module is the narrow bridge between those concerns. Consumers
 * provide their own database adapter and account policy, while the package
 * owns the resolution order and refuses unsafe email-based adoption by
 * default.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveExternalIdentity = resolveExternalIdentity;
exports.linkExternalIdentity = linkExternalIdentity;
function normalizedVerifiedEmail(identity) {
    // Allowlist the two positive states, don't exclude 'none': TypeScript can't
    // stop a JS consumer or a deserialized object from carrying undefined/bogus
    // emailAuthority, and `!== 'none'` treats that as verified — fail OPEN.
    // `!== 'asserted' && !== 'hosted'` fails CLOSED on anything unrecognized.
    if ((identity.emailAuthority !== 'asserted' && identity.emailAuthority !== 'hosted') || !identity.email)
        return null;
    const email = identity.email.trim().toLowerCase();
    return email.length > 0 ? email : null;
}
function sameEmail(account, email) {
    return account.email?.trim().toLowerCase() === email;
}
/**
 * Record an audit event without ever letting a broken sink break the
 * caller's otherwise-correct outcome — the same guarantee
 * express-security-kit's `AuditBuffer` makes for its own sink (see
 * `AuditBuffer.safeWarn`): isolate the failure, then surface it via
 * `console.warn` (itself guarded, so a hostile/throwing console can't break
 * this either) instead of silently dropping it.
 */
/**
 * Record an audit event without ever letting a broken sink break the
 * caller's otherwise-correct outcome — the same guarantee
 * express-security-kit's `AuditBuffer` makes for its own sink (see
 * `AuditBuffer.safeWarn`): isolate the failure, then surface it via
 * `console.warn` (itself guarded, so a hostile/throwing console can't break
 * this either) instead of silently dropping it.
 */
async function audit(sink, event) {
    if (!sink)
        return;
    try {
        await sink.record(event);
    }
    catch (err) {
        try {
            console.warn('[auth-kit] identity audit sink failed', err);
        }
        catch {
            // console itself must never break the caller.
        }
    }
}
/**
 * Shared refusal path for {@link linkExternalIdentity}: every refusal branch
 * routes through here so the audit call can't drift out of sync with a new
 * outcome (or silently get skipped on a new return) the way per-branch calls
 * did before.
 */
async function refuseLink(auditSink, accountId, identity, reason) {
    await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId, identity, reason });
}
/**
 * Resolve an unauthenticated OAuth callback. It always starts with issuer +
 * subject; it NEVER auto-links an independently verified local account by
 * email, and it never claims a credentialed placeholder unless the policy
 * implements `mayClaimCredentialedPlaceholder` and returns `true` for it. By
 * default the only email-based mutation allowed here is an explicit
 * app-policy-approved claim of an uncredentialed, unverified placeholder.
 */
async function resolveExternalIdentity(store, policy, identity, auditSink) {
    const existingIdentity = await store.findAccountByExternalIdentity(identity);
    if (existingIdentity) {
        if (existingIdentity.disabled) {
            await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: existingIdentity.id, identity, reason: 'disabled' });
            return { outcome: 'disabled', account: existingIdentity };
        }
        return { outcome: 'returning', account: existingIdentity };
    }
    const email = normalizedVerifiedEmail(identity);
    if (!email) {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', identity, reason: 'unverified-email' });
        return { outcome: 'unverified-email' };
    }
    const accountByEmail = await store.findAccountByNormalizedEmail(email);
    if (accountByEmail) {
        if (accountByEmail.disabled) {
            await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: accountByEmail.id, identity, reason: 'disabled' });
            return { outcome: 'disabled', account: accountByEmail };
        }
        // Engine-level hard bar, checked before EITHER policy hook runs: a claim
        // nulls a placeholder's password and revokes its sessions, so it may
        // proceed only when the issuer is authoritative for the address RIGHT
        // NOW. `'asserted'` proves the holder controlled the external account,
        // not that they control the mailbox today, so it is never enough here —
        // an app that wants a different bar expresses that through what its
        // adapter emits as `emailAuthority`, not through a policy hook. Leading
        // both `credentialsPermit` and `eligiblePlaceholder` with this flag means
        // a non-authoritative identity short-circuits before
        // `mayClaimCredentialedPlaceholder` or `mayClaimPlaceholder` ever fires —
        // those hooks may audit or rate-limit, so calling them for a claim that
        // can never proceed would pollute that trail.
        const authoritative = identity.emailAuthority === 'hosted';
        const credentialsPermit = authoritative &&
            (!accountByEmail.hasCredentials ||
                (await policy.mayClaimCredentialedPlaceholder?.(accountByEmail, identity)) === true);
        const eligiblePlaceholder = authoritative &&
            credentialsPermit &&
            !accountByEmail.emailVerified &&
            sameEmail(accountByEmail, email) &&
            (await policy.mayClaimPlaceholder(accountByEmail, identity));
        if (eligiblePlaceholder) {
            const claim = await store.claimPlaceholder(accountByEmail.id, identity);
            if (claim.status === 'claimed') {
                await audit(auditSink, { type: 'EXTERNAL_IDENTITY_CLAIMED', accountId: claim.account.id, identity });
                return { outcome: 'claimed-placeholder', account: claim.account };
            }
            if (claim.status === 'identity-in-use') {
                const winner = await store.findAccountByExternalIdentity(identity);
                if (winner && !winner.disabled)
                    return { outcome: 'returning', account: winner };
                return { outcome: 'identity-in-use' };
            }
        }
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: accountByEmail.id, identity, reason: 'account-exists' });
        return { outcome: 'account-exists', account: accountByEmail };
    }
    if (!await policy.mayProvision(identity)) {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', identity, reason: 'provisioning-refused' });
        return { outcome: 'provisioning-refused' };
    }
    const provisioned = await store.provisionAccount(identity);
    if ('status' in provisioned) {
        const winner = await store.findAccountByExternalIdentity(identity);
        if (winner && !winner.disabled)
            return { outcome: 'returning', account: winner };
        return { outcome: 'identity-in-use' };
    }
    await audit(auditSink, { type: 'EXTERNAL_IDENTITY_PROVISIONED', accountId: provisioned.id, identity });
    return { outcome: 'provisioned', account: provisioned };
}
/**
 * Link a proven external identity to the current local account. The caller is
 * responsible for proving the current local session and same-browser OAuth
 * ceremony; this function owns the remaining account and identity invariants.
 */
async function linkExternalIdentity(store, policy, currentAccountId, identity, auditSink) {
    const account = await store.findAccountById(currentAccountId);
    if (!account) {
        // No account exists for the attempted id — audit against the ATTEMPTED
        // id (there is no real account to attribute it to). That the id doesn't
        // resolve is itself the interesting signal: this is exactly the shape of
        // an account-enumeration probe, not a caller bug to stay silent about.
        await refuseLink(auditSink, currentAccountId, identity, 'not-found');
        return { outcome: 'not-found' };
    }
    if (account.disabled) {
        await refuseLink(auditSink, account.id, identity, 'disabled');
        return { outcome: 'disabled', account };
    }
    const email = normalizedVerifiedEmail(identity);
    if (!email) {
        await refuseLink(auditSink, account.id, identity, 'unverified-email');
        return { outcome: 'unverified-email' };
    }
    if (policy.requireMatchingEmailForLink !== false && !sameEmail(account, email)) {
        await refuseLink(auditSink, account.id, identity, 'email-mismatch');
        return { outcome: 'email-mismatch', account };
    }
    const owner = await store.findAccountByExternalIdentity(identity);
    if (owner) {
        if (owner.id === account.id)
            return { outcome: 'already-linked', account };
        await refuseLink(auditSink, account.id, identity, 'identity-in-use');
        return { outcome: 'identity-in-use' };
    }
    const result = await store.bindExternalIdentity(account.id, identity);
    if (result.status === 'linked') {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_LINKED', accountId: account.id, identity });
        return { outcome: 'linked', account };
    }
    if (result.status === 'already-linked')
        return { outcome: 'already-linked', account };
    if (result.status === 'account-already-linked') {
        await refuseLink(auditSink, account.id, identity, 'account-already-linked');
        return { outcome: 'account-already-linked' };
    }
    // `store.bindExternalIdentity` promises a real `not-eligible` refusal
    // reason (see `BindResult`); map it through directly instead of collapsing
    // it into the generic `identity-in-use` catch-all below, which would tell
    // the caller "this identity belongs to someone else" when the truth is
    // "this account is not eligible to link".
    if (result.status === 'not-eligible') {
        await refuseLink(auditSink, account.id, identity, 'not-eligible');
        return { outcome: 'not-eligible' };
    }
    await refuseLink(auditSink, account.id, identity, 'identity-in-use');
    return { outcome: 'identity-in-use' };
}
