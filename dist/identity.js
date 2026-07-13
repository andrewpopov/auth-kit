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
    if (!identity.emailVerified || !identity.email)
        return null;
    const email = identity.email.trim().toLowerCase();
    return email.length > 0 ? email : null;
}
function sameEmail(account, email) {
    return account.email?.trim().toLowerCase() === email;
}
async function audit(sink, event) {
    await sink?.record(event);
}
/**
 * Resolve an unauthenticated OAuth callback. It always starts with issuer +
 * subject; it NEVER auto-links a credentialed or independently verified local
 * account by email. The only email-based mutation allowed here is an explicit
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
        const eligiblePlaceholder = !accountByEmail.hasCredentials &&
            !accountByEmail.emailVerified &&
            sameEmail(accountByEmail, email) &&
            await policy.mayClaimPlaceholder(accountByEmail, identity);
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
    if (!account)
        return { outcome: 'not-found' };
    if (account.disabled) {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: account.id, identity, reason: 'disabled' });
        return { outcome: 'disabled', account };
    }
    const email = normalizedVerifiedEmail(identity);
    if (!email)
        return { outcome: 'unverified-email' };
    if (policy.requireMatchingEmailForLink !== false && !sameEmail(account, email)) {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: account.id, identity, reason: 'email-mismatch' });
        return { outcome: 'email-mismatch', account };
    }
    const owner = await store.findAccountByExternalIdentity(identity);
    if (owner) {
        if (owner.id === account.id)
            return { outcome: 'already-linked', account };
        return { outcome: 'identity-in-use' };
    }
    const result = await store.bindExternalIdentity(account.id, identity);
    if (result.status === 'linked') {
        await audit(auditSink, { type: 'EXTERNAL_IDENTITY_LINKED', accountId: account.id, identity });
        return { outcome: 'linked', account };
    }
    if (result.status === 'already-linked')
        return { outcome: 'already-linked', account };
    if (result.status === 'account-already-linked')
        return { outcome: 'account-already-linked' };
    return { outcome: 'identity-in-use' };
}
