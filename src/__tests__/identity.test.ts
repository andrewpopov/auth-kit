import { describe, expect, it, vi } from 'vitest';
import {
  linkExternalIdentity,
  resolveExternalIdentity,
  type AccountIdentityPolicy,
  type AccountIdentityRecord,
  type BindResult,
  type ExternalIdentity,
  type ExternalIdentityStore,
  type IdentityAuditEvent,
  type IdentityAuditSink,
} from '../index';

const google = (overrides: Partial<ExternalIdentity> = {}): ExternalIdentity => ({
  issuer: 'https://accounts.google.com', subject: 'google-subject-1', email: 'owner@example.test', emailAuthority: 'hosted', ...overrides,
});

class MemoryStore implements ExternalIdentityStore {
  accounts = new Map<string, AccountIdentityRecord>();
  identities = new Map<string, string>();
  constructor(accounts: AccountIdentityRecord[] = []) { accounts.forEach(a => this.accounts.set(a.id, { ...a })); }
  private key(identity: Pick<ExternalIdentity, 'issuer' | 'subject'>) { return `${identity.issuer}|${identity.subject}`; }
  async findAccountByExternalIdentity(identity: Pick<ExternalIdentity, 'issuer' | 'subject'>) {
    const id = this.identities.get(this.key(identity)); return id ? this.accounts.get(id) ?? null : null;
  }
  async findAccountById(id: string) { return this.accounts.get(id) ?? null; }
  async findAccountByNormalizedEmail(email: string) {
    return [...this.accounts.values()].find(a => a.email?.toLowerCase() === email) ?? null;
  }
  async bindExternalIdentity(accountId: string, identity: ExternalIdentity) {
    const key = this.key(identity); const owner = this.identities.get(key);
    if (owner && owner !== accountId) return { status: 'identity-in-use' } as const;
    if (owner === accountId) return { status: 'already-linked' } as const;
    this.identities.set(key, accountId); return { status: 'linked' } as const;
  }
  async claimPlaceholder(accountId: string, identity: ExternalIdentity) {
    const account = this.accounts.get(accountId); const owner = this.identities.get(this.key(identity));
    if (owner) return { status: 'identity-in-use' } as const;
    if (!account || account.emailVerified || account.disabled) return { status: 'not-eligible' } as const;
    this.identities.set(this.key(identity), accountId);
    const claimed = { ...account, emailVerified: true };
    this.accounts.set(accountId, claimed);
    return { status: 'claimed', account: claimed } as const;
  }
  async provisionAccount(identity: ExternalIdentity) {
    if (this.identities.has(this.key(identity))) return { status: 'identity-in-use' } as const;
    const account = { id: `new-${this.accounts.size + 1}`, email: identity.email, emailVerified: true, disabled: false, hasCredentials: false };
    this.accounts.set(account.id, account); this.identities.set(this.key(identity), account.id); return account;
  }
}

/** A minimal store whose `bindExternalIdentity` always returns a fixed, forced result — for exercising store outcomes (`not-eligible`, `account-already-linked`) MemoryStore's own bind logic never produces. */
function storeWithBindResult(account: AccountIdentityRecord, bindResult: BindResult): ExternalIdentityStore {
  return {
    async findAccountByExternalIdentity() { return null; },
    async findAccountById(id) { return id === account.id ? account : null; },
    async findAccountByNormalizedEmail() { return null; },
    async bindExternalIdentity() { return bindResult; },
    async claimPlaceholder() { throw new Error('not used in this test'); },
    async provisionAccount() { throw new Error('not used in this test'); },
  };
}

function collectingSink(): { sink: IdentityAuditSink; events: IdentityAuditEvent[] } {
  const events: IdentityAuditEvent[] = [];
  return { sink: { record: (event) => { events.push(event); } }, events };
}

const policy: AccountIdentityPolicy = {
  mayProvision: () => true,
  mayClaimPlaceholder: () => true,
};

describe('external identity resolution', () => {
  it('returns by issuer and subject before consulting email', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'old@example.test', emailVerified: false, disabled: false, hasCredentials: true }]);
    await store.bindExternalIdentity('u1', google());
    await expect(resolveExternalIdentity(store, policy, google({ email: 'new@example.test' }))).resolves.toMatchObject({ outcome: 'returning', account: { id: 'u1' } });
  });

  it('never auto-links a credentialed matching-email account', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const result = await resolveExternalIdentity(store, policy, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
    expect(await store.findAccountByExternalIdentity(google())).toBeNull();
  });

  it('claims only an app-policy-approved unverified, uncredentialed placeholder', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    const result = await resolveExternalIdentity(store, policy, google());
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1', emailVerified: true } });
  });

  it('refuses unverified email before any email-based mutation', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    await expect(resolveExternalIdentity(store, policy, google({ emailAuthority: 'none' }))).resolves.toEqual({ outcome: 'unverified-email' });
    expect(await store.findAccountByExternalIdentity(google())).toBeNull();
  });

  it('requires an explicit matching-email link for an existing account', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    await expect(linkExternalIdentity(store, policy, 'u1', google())).resolves.toMatchObject({ outcome: 'linked', account: { id: 'u1' } });
    await expect(linkExternalIdentity(store, policy, 'u1', google())).resolves.toMatchObject({ outcome: 'already-linked' });
  });

  it('canaries the email-match guard: a different verified Google email cannot link', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    await expect(linkExternalIdentity(store, policy, 'u1', google({ email: 'attacker@example.test' }))).resolves.toMatchObject({ outcome: 'email-mismatch' });
    expect(await store.findAccountByExternalIdentity(google())).toBeNull();
  });

  it('refuses an identity already linked to another account', async () => {
    const store = new MemoryStore([
      { id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true },
      { id: 'u2', email: 'other@example.test', emailVerified: true, disabled: false, hasCredentials: true },
    ]);
    await store.bindExternalIdentity('u2', google());
    await expect(linkExternalIdentity(store, policy, 'u1', google())).resolves.toEqual({ outcome: 'identity-in-use' });
  });
});

describe('linkExternalIdentity: not-eligible outcome (Finding 1)', () => {
  it('surfaces not-eligible distinctly from identity-in-use when the store refuses the bind as ineligible', async () => {
    const account: AccountIdentityRecord = { id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true };
    const store = storeWithBindResult(account, { status: 'not-eligible' });
    const result = await linkExternalIdentity(store, policy, 'u1', google());
    expect(result).toEqual({ outcome: 'not-eligible' });
  });
});

describe('linkExternalIdentity: audit trail (Finding 2)', () => {
  it('audits a disabled-account refusal', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: true, hasCredentials: true }]);
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toMatchObject({ outcome: 'disabled' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity: google(), reason: 'disabled' }]);
  });

  it('audits an unverified-email refusal', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const { sink, events } = collectingSink();
    const identity = google({ emailAuthority: 'none' });
    await expect(linkExternalIdentity(store, policy, 'u1', identity, sink)).resolves.toEqual({ outcome: 'unverified-email' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity, reason: 'unverified-email' }]);
  });

  it('audits an email-mismatch refusal', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const { sink, events } = collectingSink();
    const identity = google({ email: 'attacker@example.test' });
    await expect(linkExternalIdentity(store, policy, 'u1', identity, sink)).resolves.toMatchObject({ outcome: 'email-mismatch' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity, reason: 'email-mismatch' }]);
  });

  it('audits an identity-already-linked-to-another-account refusal', async () => {
    const store = new MemoryStore([
      { id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true },
      { id: 'u2', email: 'other@example.test', emailVerified: true, disabled: false, hasCredentials: true },
    ]);
    await store.bindExternalIdentity('u2', google());
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toEqual({ outcome: 'identity-in-use' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity: google(), reason: 'identity-in-use' }]);
  });

  it('audits an account-already-linked refusal from the store', async () => {
    const account: AccountIdentityRecord = { id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true };
    const store = storeWithBindResult(account, { status: 'account-already-linked' });
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toEqual({ outcome: 'account-already-linked' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity: google(), reason: 'account-already-linked' }]);
  });

  it('audits the new not-eligible refusal from the store', async () => {
    const account: AccountIdentityRecord = { id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true };
    const store = storeWithBindResult(account, { status: 'not-eligible' });
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toEqual({ outcome: 'not-eligible' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'u1', identity: google(), reason: 'not-eligible' }]);
  });

  it('audits a not-found refusal, attributed to the ATTEMPTED account id (no real account exists)', async () => {
    const store = new MemoryStore([]);
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'no-such-account', google(), sink)).resolves.toEqual({ outcome: 'not-found' });
    expect(events).toEqual([{ type: 'EXTERNAL_IDENTITY_REFUSED', accountId: 'no-such-account', identity: google(), reason: 'not-found' }]);
  });

  it('does NOT audit a successful link', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toMatchObject({ outcome: 'linked' });
    expect(events.filter(event => event.type === 'EXTERNAL_IDENTITY_REFUSED')).toEqual([]);
  });

  it('does NOT audit an idempotent already-linked re-link of the same account', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    await store.bindExternalIdentity('u1', google());
    const { sink, events } = collectingSink();
    await expect(linkExternalIdentity(store, policy, 'u1', google(), sink)).resolves.toMatchObject({ outcome: 'already-linked' });
    expect(events).toEqual([]);
  });
});

describe('linkExternalIdentity: a broken audit sink never breaks the refusal outcome (Finding B)', () => {
  it('a SYNCHRONOUSLY THROWING sink still lets the typed refusal outcome come back intact', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: true, hasCredentials: true }]);
    const throwingSink: IdentityAuditSink = { record: () => { throw new Error('sink exploded'); } };
    await expect(linkExternalIdentity(store, policy, 'u1', google(), throwingSink)).resolves.toMatchObject({ outcome: 'disabled' });
  });

  it('an ASYNCHRONOUSLY REJECTING sink still lets the typed refusal outcome come back intact', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: true, hasCredentials: true }]);
    const rejectingSink: IdentityAuditSink = { record: () => Promise.reject(new Error('sink exploded')) };
    await expect(linkExternalIdentity(store, policy, 'u1', google(), rejectingSink)).resolves.toMatchObject({ outcome: 'disabled' });
  });

  it('surfaces (does not silently swallow) the sink failure via console.warn', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: true, hasCredentials: true }]);
    const sinkError = new Error('sink exploded');
    const throwingSink: IdentityAuditSink = { record: () => { throw sinkError; } };
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await expect(linkExternalIdentity(store, policy, 'u1', google(), throwingSink)).resolves.toMatchObject({ outcome: 'disabled' });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('audit sink failed'), sinkError);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('a broken sink does not stop a SUCCESSFUL link from returning its outcome either (audit() is shared, not refuseLink-specific)', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const throwingSink: IdentityAuditSink = { record: () => { throw new Error('sink exploded'); } };
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await expect(linkExternalIdentity(store, policy, 'u1', google(), throwingSink)).resolves.toMatchObject({ outcome: 'linked' });
    } finally {
      warnSpy.mockRestore();
    }
  });
});

describe('opt-in: claiming a credentialed placeholder', () => {
  const credentialedUnverified = () =>
    new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: true }]);

  it('default (no mayClaimCredentialedPlaceholder method) still refuses — unchanged behavior', async () => {
    const store = credentialedUnverified();
    const result = await resolveExternalIdentity(store, policy, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
    expect(await store.findAccountByExternalIdentity(google())).toBeNull();
  });

  it('method returns true -> claims the credentialed placeholder', async () => {
    const store = credentialedUnverified();
    const optedIn: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder: () => true };
    const result = await resolveExternalIdentity(store, optedIn, google());
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1', emailVerified: true } });
  });

  it('method returns false -> still refused', async () => {
    const store = credentialedUnverified();
    const declined: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder: () => false };
    const result = await resolveExternalIdentity(store, declined, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
  });

  it('a truthy-but-not-exactly-true return value does NOT enable the claim', async () => {
    const store = credentialedUnverified();
    const sloppy: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder: () => 1 as unknown as boolean };
    const result = await resolveExternalIdentity(store, sloppy, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
  });

  it('emailVerified is an absolute bar: even with the opt-in returning true, a verified matching-email credentialed account is never claimed', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const optedIn: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder: () => true };
    const result = await resolveExternalIdentity(store, optedIn, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
    expect(await store.findAccountByExternalIdentity(google())).toBeNull();
  });

  it('mayClaimPlaceholder remains mandatory: opt-in true but mayClaimPlaceholder false -> still refused', async () => {
    const store = credentialedUnverified();
    const optedIn: AccountIdentityPolicy = {
      ...policy,
      mayClaimPlaceholder: () => false,
      mayClaimCredentialedPlaceholder: () => true,
    };
    const result = await resolveExternalIdentity(store, optedIn, google());
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
  });

  it('uncredentialed + unverified placeholder still claims with no opt-in configured (no regression)', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    const result = await resolveExternalIdentity(store, policy, google());
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1', emailVerified: true } });
  });
});

describe('emailAuthority', () => {
  it('claims a hosted-authority placeholder (gmail.com address)', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@gmail.com', emailVerified: false, disabled: false, hasCredentials: false }]);
    const identity = google({ email: 'owner@gmail.com', emailAuthority: 'hosted' });
    const result = await resolveExternalIdentity(store, policy, identity);
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1' } });
  });

  it('claims a hosted-authority placeholder (Workspace address, hd set)', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@workspace-domain.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    const identity = google({ email: 'owner@workspace-domain.test', emailAuthority: 'hosted' });
    const result = await resolveExternalIdentity(store, policy, identity);
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1' } });
  });

  it('refuses a claim for asserted-only authority (uncredentialed placeholder)', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    const mayClaimPlaceholder = vi.fn(() => true);
    const spiedPolicy: AccountIdentityPolicy = { ...policy, mayClaimPlaceholder };
    const identity = google({ emailAuthority: 'asserted' });
    const result = await resolveExternalIdentity(store, spiedPolicy, identity);
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
    expect(await store.findAccountByExternalIdentity(identity)).toBeNull();
    // Symmetric to the mayClaimCredentialedPlaceholder assertion below: the
    // engine bar precedes BOTH policy hooks, not just the one with
    // credentials to gate.
    expect(mayClaimPlaceholder).not.toHaveBeenCalled();
  });

  it('refuses a claim for asserted-only authority even when mayClaimCredentialedPlaceholder would permit it — the engine bar precedes the policy hook', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: true }]);
    const mayClaimCredentialedPlaceholder = vi.fn(() => true);
    const optedIn: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder };
    const identity = google({ emailAuthority: 'asserted' });
    const result = await resolveExternalIdentity(store, optedIn, identity);
    expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'u1' } });
    expect(await store.findAccountByExternalIdentity(identity)).toBeNull();
    // The bar must precede the hook, not merely the outcome it gates: prove
    // the hook was never invoked for a non-authoritative identity, not just
    // that its permissive answer didn't matter.
    expect(mayClaimCredentialedPlaceholder).not.toHaveBeenCalled();
  });

  it('a hosted, credentialed placeholder DOES invoke mayClaimCredentialedPlaceholder — the bar gates the hook, it does not disable it', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: true }]);
    const mayClaimCredentialedPlaceholder = vi.fn(() => true);
    const optedIn: AccountIdentityPolicy = { ...policy, mayClaimCredentialedPlaceholder };
    const identity = google({ emailAuthority: 'hosted' });
    const result = await resolveExternalIdentity(store, optedIn, identity);
    expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'u1', emailVerified: true } });
    expect(mayClaimCredentialedPlaceholder).toHaveBeenCalledTimes(1);
    expect(mayClaimCredentialedPlaceholder).toHaveBeenCalledWith(expect.objectContaining({ id: 'u1' }), identity);
  });

  it('provisioning still succeeds for asserted-only authority', async () => {
    const store = new MemoryStore([]);
    const identity = google({ email: 'new-user@example.test', emailAuthority: 'asserted' });
    const result = await resolveExternalIdentity(store, policy, identity);
    expect(result.outcome).toBe('provisioned');
  });

  it('linkExternalIdentity still succeeds for asserted-only authority', async () => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: true, disabled: false, hasCredentials: true }]);
    const identity = google({ emailAuthority: 'asserted' });
    await expect(linkExternalIdentity(store, policy, 'u1', identity)).resolves.toMatchObject({ outcome: 'linked', account: { id: 'u1' } });
  });

  // A missing/invalid emailAuthority must fail CLOSED, not open. TypeScript
  // rejects these at compile time, but a plain-JS consumer or an object
  // deserialized from JSON (or read back from a stale build) bypasses that
  // entirely, so the cast simulates the real runtime threat, not a contrived
  // one.
  it.each([undefined, 'verified', true])('emailAuthority=%s yields unverified-email, never claims/provisions/links', async (badValue) => {
    const store = new MemoryStore([{ id: 'u1', email: 'owner@example.test', emailVerified: false, disabled: false, hasCredentials: false }]);
    const identity = { ...google(), emailAuthority: badValue } as unknown as ExternalIdentity;
    const result = await resolveExternalIdentity(store, policy, identity);
    expect(result).toEqual({ outcome: 'unverified-email' });
    expect(await store.findAccountByExternalIdentity(identity)).toBeNull();
  });
});
