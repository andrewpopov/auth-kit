import { describe, expect, it } from 'vitest';
import { runExternalIdentityStoreConformanceTests } from '../conformance';
import type { AccountIdentityRecord, ExternalIdentity, ExternalIdentityStore } from '../identity';

class MemoryIdentityStore implements ExternalIdentityStore {
  private accounts = new Map<string, AccountIdentityRecord>();
  private identities = new Map<string, string>();
  private key(identity: Pick<ExternalIdentity, 'issuer' | 'subject'>) { return `${identity.issuer}|${identity.subject}`; }
  async findAccountByExternalIdentity(identity: Pick<ExternalIdentity, 'issuer' | 'subject'>) { const id = this.identities.get(this.key(identity)); return id ? this.accounts.get(id) ?? null : null; }
  async findAccountById(id: string) { return this.accounts.get(id) ?? null; }
  async findAccountByNormalizedEmail(email: string) { return [...this.accounts.values()].find(account => account.email?.toLowerCase() === email) ?? null; }
  async bindExternalIdentity(accountId: string, identity: ExternalIdentity) {
    const key = this.key(identity); const owner = this.identities.get(key);
    if (owner && owner !== accountId) return { status: 'identity-in-use' } as const;
    if (owner === accountId) return { status: 'already-linked' } as const;
    this.identities.set(key, accountId); return { status: 'linked' } as const;
  }
  async claimPlaceholder(accountId: string, identity: ExternalIdentity) {
    const account = this.accounts.get(accountId);
    if (!account || account.hasCredentials || account.emailVerified || account.disabled) return { status: 'not-eligible' } as const;
    if (this.identities.has(this.key(identity))) return { status: 'identity-in-use' } as const;
    const claimed = { ...account, emailVerified: true }; this.accounts.set(accountId, claimed); this.identities.set(this.key(identity), accountId);
    return { status: 'claimed', account: claimed } as const;
  }
  async provisionAccount(identity: ExternalIdentity) {
    if (this.identities.has(this.key(identity))) return { status: 'identity-in-use' } as const;
    const account = { id: `provisioned-${this.accounts.size + 1}`, email: identity.email, emailVerified: true, disabled: false, hasCredentials: false };
    this.accounts.set(account.id, account); this.identities.set(this.key(identity), account.id); return account;
  }
  async create(account: AccountIdentityRecord) { this.accounts.set(account.id, account); }
}

runExternalIdentityStoreConformanceTests(
  () => new MemoryIdentityStore(),
  async store => ({ createAccount: account => (store as MemoryIdentityStore).create(account) }),
  { describe, it, expect },
  { concurrency: 8 },
);
