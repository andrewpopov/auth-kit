import { describe, expect, it } from 'vitest';
import {
  linkExternalIdentity,
  resolveExternalIdentity,
  type AccountIdentityPolicy,
  type AccountIdentityRecord,
  type ExternalIdentity,
  type ExternalIdentityStore,
} from '../index';

const google = (overrides: Partial<ExternalIdentity> = {}): ExternalIdentity => ({
  issuer: 'https://accounts.google.com', subject: 'google-subject-1', email: 'owner@example.test', emailVerified: true, ...overrides,
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
    if (!account || account.hasCredentials || account.emailVerified || account.disabled) return { status: 'not-eligible' } as const;
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
    await expect(resolveExternalIdentity(store, policy, google({ emailVerified: false }))).resolves.toEqual({ outcome: 'unverified-email' });
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
