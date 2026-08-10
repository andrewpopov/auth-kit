import { describe, expect, it } from 'vitest';
import { runExternalIdentityStoreConformanceTests, type ConformanceTestHarness } from '../conformance';
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

/**
 * Deliberately NON-atomic `claimPlaceholder`: a genuine `await` sits between
 * the eligibility/uniqueness check and the write, so N concurrent callers can
 * all pass the check before any of them commits — exactly the "select
 * followed by an unconditional update" bug the conformance suite's doc
 * comment warns adapter authors about (`src/conformance.ts`). Everything else
 * mirrors `MemoryIdentityStore` and stays atomic, so only the new
 * placeholder-claim race test (Finding 4) is expected to catch this — proving
 * that test isn't vacuous.
 */
class NonAtomicPlaceholderStore implements ExternalIdentityStore {
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
    // The bug: a real await between the check above and the write below —
    // every concurrent caller observes the pre-write state before any of
    // them commits.
    await new Promise<void>(resolve => setImmediate(resolve));
    const claimed = { ...account, emailVerified: true };
    this.accounts.set(accountId, claimed);
    this.identities.set(this.key(identity), accountId);
    return { status: 'claimed', account: claimed } as const;
  }
  async provisionAccount(identity: ExternalIdentity) {
    if (this.identities.has(this.key(identity))) return { status: 'identity-in-use' } as const;
    const account = { id: `provisioned-${this.accounts.size + 1}`, email: identity.email, emailVerified: true, disabled: false, hasCredentials: false };
    this.accounts.set(account.id, account); this.identities.set(this.key(identity), account.id); return account;
  }
  async create(account: AccountIdentityRecord) { this.accounts.set(account.id, account); }
}

/**
 * Runs `runExternalIdentityStoreConformanceTests` against a recording harness
 * instead of real vitest `describe`/`it`, so a failing inner test is captured
 * as data (name + thrown error) rather than failing THIS test file outright.
 * Shared by both meta-tests below.
 */
async function runConformanceSuiteRecorded(
  makeStore: () => ExternalIdentityStore,
  createAccount: (store: ExternalIdentityStore, account: AccountIdentityRecord) => Promise<void>,
  options?: { concurrency?: number },
): Promise<{ name: string; error: unknown }[]> {
  const pending: Promise<void>[] = [];
  const results: { name: string; error: unknown }[] = [];
  const recordingHarness: ConformanceTestHarness = {
    describe: (_name, fn) => fn(),
    it: (name, fn) => {
      pending.push(
        Promise.resolve()
          .then(() => fn())
          .then(
            () => { results.push({ name, error: undefined }); },
            (error: unknown) => { results.push({ name, error }); },
          ),
      );
    },
    expect,
  };
  runExternalIdentityStoreConformanceTests(makeStore, async store => ({ createAccount: account => createAccount(store, account) }), recordingHarness, options);
  await Promise.all(pending);
  return results;
}

describe('meta: the placeholder-claim race (Finding 4) actually catches a non-atomic adapter', () => {
  it('fails ONLY the placeholder-claim-race conformance test against NonAtomicPlaceholderStore — checked across every registered result, not a hand-picked subset', async () => {
    const results = await runConformanceSuiteRecorded(
      () => new NonAtomicPlaceholderStore(),
      (store, account) => (store as NonAtomicPlaceholderStore).create(account),
      { concurrency: 20 },
    );

    // Guard against a truncated/empty `results` making the set comparison
    // below pass vacuously — the suite must actually have registered (and
    // run) every test it's supposed to.
    expect(results.length).toBeGreaterThan(1);

    const raceTestNames = new Set(
      results.map(result => result.name).filter(name => name.includes('claimPlaceholder single-use under real concurrency')),
    );
    // Exactly one test matches that name pattern — if this is 0, the rename
    // above drifted from what conformance.ts actually registers; if more
    // than 1, the match is too broad to isolate anything.
    expect(raceTestNames.size).toBe(1);

    const failedNames = new Set(results.filter(result => result.error !== undefined).map(result => result.name));
    // The failure set must be EXACTLY the race test — every other registered
    // result (bind race, sequential placeholder claim, resolution tests,
    // ...) must still pass against this fixture, proving the failure is
    // specific to the non-atomic claimPlaceholder, not a broken fixture or a
    // suite that fails everything indiscriminately. Asserted over the WHOLE
    // result set, not a few names picked in advance.
    expect(failedNames).toEqual(raceTestNames);
  });
});

/**
 * Correct and atomic (like `MemoryIdentityStore`), but its `create` fixture
 * helper ALSO enforces a unique-normalized-email constraint — the same
 * constraint plenty of real, otherwise-conforming adapters have on their
 * accounts table. Exists to prove the placeholder-claim race test races ONE
 * placeholder per round (unique email per round) rather than several
 * placeholders sharing an email, which would spuriously fail here.
 */
class UniqueEmailIdentityStore implements ExternalIdentityStore {
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
  async create(account: AccountIdentityRecord) {
    if (account.email && [...this.accounts.values()].some(existing => existing.email?.toLowerCase() === account.email?.toLowerCase())) {
      throw new Error(`UniqueEmailIdentityStore: duplicate normalized email "${account.email}"`);
    }
    this.accounts.set(account.id, account);
  }
}

describe('meta: the placeholder-claim race (Finding 4) does not spuriously fail against an adapter enforcing unique emails', () => {
  it('every registered conformance test passes against UniqueEmailIdentityStore — no false failure from racing several same-email placeholders', async () => {
    const results = await runConformanceSuiteRecorded(() => new UniqueEmailIdentityStore(), (store, account) => (store as UniqueEmailIdentityStore).create(account));

    expect(results.length).toBeGreaterThan(1);
    const failed = results.filter(result => result.error !== undefined);
    expect(failed).toEqual([]);
  });
});
