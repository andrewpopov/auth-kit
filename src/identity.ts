/**
 * Provider-neutral external identity binding.
 *
 * OAuth proves an identity; it does not authorize a mutation of an app's user
 * model. This module is the narrow bridge between those concerns. Consumers
 * provide their own database adapter and account policy, while the package
 * owns the resolution order and refuses unsafe email-based adoption by
 * default.
 */

export interface ExternalIdentity {
  /** OIDC issuer, normalized by the provider adapter (for Google: https://accounts.google.com). */
  issuer: string;
  /** Provider-stable subject. This, not email, is the durable identity key. */
  subject: string;
  email: string | null;
  emailVerified: boolean;
  name?: string | null;
  picture?: string | null;
}

export interface AccountIdentityRecord {
  id: string;
  email: string | null;
  /** Disabled/deactivated accounts never receive an identity binding or session. */
  disabled: boolean;
  /** A password, passkey, or another first-party credential protects this account. */
  hasCredentials: boolean;
  /** Whether the app has independently verified the local email address. */
  emailVerified: boolean;
}

export type BindResult =
  | { status: 'linked' }
  | { status: 'already-linked' }
  | { status: 'identity-in-use' }
  | { status: 'account-already-linked' }
  | { status: 'not-eligible' };

export type ClaimResult =
  | { status: 'claimed'; account: AccountIdentityRecord }
  | { status: 'identity-in-use' }
  | { status: 'not-eligible' };

/**
 * The only storage surface the identity engine needs. Implementations must
 * enforce a unique (issuer, subject) identity constraint and make bind/claim
 * decisions atomic. An ORM user model, roles, memberships, and invitations do
 * not belong in this package.
 */
export interface ExternalIdentityStore {
  findAccountByExternalIdentity(identity: Pick<ExternalIdentity, 'issuer' | 'subject'>): Promise<AccountIdentityRecord | null>;
  findAccountById(accountId: string): Promise<AccountIdentityRecord | null>;
  findAccountByNormalizedEmail(email: string): Promise<AccountIdentityRecord | null>;
  /** Atomic compare-and-swap: only bind an unbound account and never steal a subject. */
  bindExternalIdentity(accountId: string, identity: ExternalIdentity): Promise<BindResult>;
  /** Atomic claim for an adapter-verified placeholder. */
  claimPlaceholder(accountId: string, identity: ExternalIdentity): Promise<ClaimResult>;
  /** Atomically create/provision an account with the external identity bound. */
  provisionAccount(identity: ExternalIdentity): Promise<AccountIdentityRecord | { status: 'identity-in-use' }>;
}

export interface AccountIdentityPolicy {
  /** New-account creation is a product decision, never an OAuth default. */
  mayProvision(identity: ExternalIdentity): boolean | Promise<boolean>;
  /**
   * Placeholder claims are intentionally narrow. The engine already requires a
   * verified matching email and no first-party credentials; apps may impose
   * invitation, tenancy, or allowlist checks here.
   */
  mayClaimPlaceholder(account: AccountIdentityRecord, identity: ExternalIdentity): boolean | Promise<boolean>;
  /** Apps can turn off profile/verified-email matching only with a deliberate policy. */
  requireMatchingEmailForLink?: boolean;
}

export interface IdentityAuditEvent {
  type: 'EXTERNAL_IDENTITY_LINKED' | 'EXTERNAL_IDENTITY_CLAIMED' | 'EXTERNAL_IDENTITY_PROVISIONED' | 'EXTERNAL_IDENTITY_REFUSED';
  accountId?: string;
  identity: Pick<ExternalIdentity, 'issuer' | 'subject'>;
  reason?: string;
}

export interface IdentityAuditSink {
  record(event: IdentityAuditEvent): void | Promise<void>;
}

export type IdentityResolution =
  | { outcome: 'returning'; account: AccountIdentityRecord }
  | { outcome: 'claimed-placeholder'; account: AccountIdentityRecord }
  | { outcome: 'provisioned'; account: AccountIdentityRecord }
  | { outcome: 'account-exists'; account: AccountIdentityRecord }
  | { outcome: 'disabled'; account: AccountIdentityRecord }
  | { outcome: 'identity-in-use' }
  | { outcome: 'provisioning-refused' }
  | { outcome: 'unverified-email' };

export type ExplicitLinkResolution =
  | { outcome: 'linked'; account: AccountIdentityRecord }
  | { outcome: 'already-linked'; account: AccountIdentityRecord }
  | { outcome: 'email-mismatch'; account: AccountIdentityRecord }
  | { outcome: 'disabled'; account: AccountIdentityRecord }
  | { outcome: 'identity-in-use' }
  | { outcome: 'account-already-linked' }
  | { outcome: 'not-found' }
  | { outcome: 'unverified-email' };

function normalizedVerifiedEmail(identity: ExternalIdentity): string | null {
  if (!identity.emailVerified || !identity.email) return null;
  const email = identity.email.trim().toLowerCase();
  return email.length > 0 ? email : null;
}

function sameEmail(account: AccountIdentityRecord, email: string): boolean {
  return account.email?.trim().toLowerCase() === email;
}

async function audit(sink: IdentityAuditSink | undefined, event: IdentityAuditEvent): Promise<void> {
  await sink?.record(event);
}

/**
 * Resolve an unauthenticated OAuth callback. It always starts with issuer +
 * subject; it NEVER auto-links a credentialed or independently verified local
 * account by email. The only email-based mutation allowed here is an explicit
 * app-policy-approved claim of an uncredentialed, unverified placeholder.
 */
export async function resolveExternalIdentity(
  store: ExternalIdentityStore,
  policy: AccountIdentityPolicy,
  identity: ExternalIdentity,
  auditSink?: IdentityAuditSink,
): Promise<IdentityResolution> {
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

    const eligiblePlaceholder =
      !accountByEmail.hasCredentials &&
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
        if (winner && !winner.disabled) return { outcome: 'returning', account: winner };
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
    if (winner && !winner.disabled) return { outcome: 'returning', account: winner };
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
export async function linkExternalIdentity(
  store: ExternalIdentityStore,
  policy: AccountIdentityPolicy,
  currentAccountId: string,
  identity: ExternalIdentity,
  auditSink?: IdentityAuditSink,
): Promise<ExplicitLinkResolution> {
  const account = await store.findAccountById(currentAccountId);
  if (!account) return { outcome: 'not-found' };
  if (account.disabled) {
    await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: account.id, identity, reason: 'disabled' });
    return { outcome: 'disabled', account };
  }
  const email = normalizedVerifiedEmail(identity);
  if (!email) return { outcome: 'unverified-email' };
  if (policy.requireMatchingEmailForLink !== false && !sameEmail(account, email)) {
    await audit(auditSink, { type: 'EXTERNAL_IDENTITY_REFUSED', accountId: account.id, identity, reason: 'email-mismatch' });
    return { outcome: 'email-mismatch', account };
  }

  const owner = await store.findAccountByExternalIdentity(identity);
  if (owner) {
    if (owner.id === account.id) return { outcome: 'already-linked', account };
    return { outcome: 'identity-in-use' };
  }

  const result = await store.bindExternalIdentity(account.id, identity);
  if (result.status === 'linked') {
    await audit(auditSink, { type: 'EXTERNAL_IDENTITY_LINKED', accountId: account.id, identity });
    return { outcome: 'linked', account };
  }
  if (result.status === 'already-linked') return { outcome: 'already-linked', account };
  if (result.status === 'account-already-linked') return { outcome: 'account-already-linked' };
  return { outcome: 'identity-in-use' };
}
