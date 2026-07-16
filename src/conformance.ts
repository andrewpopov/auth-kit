import crypto from 'crypto';
import {
  createRefreshToken,
  linkExternalIdentity,
  rotateRefreshToken,
  resolveExternalIdentity,
  hashOpaqueToken,
  generateOpaqueToken,
  DEFAULT_ROTATION_GRACE_MS,
  type AccountIdentityPolicy,
  type AccountIdentityRecord,
  type ExternalIdentity,
  type ExternalIdentityStore,
  type RefreshTokenStore,
} from './index';

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** The subset of `expect(...)`'s chainable API this suite uses — structurally satisfied by vitest's and Jest's `expect` (both are duck-typed, not imported). */
export interface ExpectLike {
  (actual: unknown): {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toMatchObject(expected: object): void;
    toBeNull(): void;
    toContain(expected: unknown): void;
    toBeGreaterThan(expected: number): void;
    not: {
      toBe(expected: unknown): void;
      toBeNull(): void;
      toContain(expected: unknown): void;
    };
    resolves: {
      toBeUndefined(): Promise<void>;
    };
  };
}

export interface IdentityStoreConformancePreparation {
  /** Insert test accounts into the real adapter without binding an external identity. */
  createAccount(account: AccountIdentityRecord): Promise<void>;
}

const conformanceIdentity: ExternalIdentity = {
  issuer: 'https://accounts.google.com',
  subject: 'auth-kit-conformance-subject',
  email: 'identity-conformance@example.test',
  emailVerified: true,
};

const conformancePolicy: AccountIdentityPolicy = {
  mayProvision: () => true,
  mayClaimPlaceholder: () => true,
};

/**
 * The test-runner primitives the suite is run against — INJECTED, same idiom
 * as the package's injected `bcrypt`. This is deliberate, not an oversight:
 * `vitest` ships ESM-only (no CJS `require()` entry point at all), so this
 * package cannot import it internally without breaking for any consumer
 * whose module resolution takes the CJS path. Injecting `describe`/`it`/
 * `expect` from the CALLER's own already-working test file sidesteps the
 * whole ESM/CJS question — and this subpath ends up with zero runtime
 * dependencies too.
 */
export interface ConformanceTestHarness {
  describe: (name: string, fn: () => void) => void;
  it: (name: string, fn: () => void | Promise<void>) => void;
  expect: ExpectLike;
}

/**
 * RefreshTokenStore PORT CONFORMANCE SUITE. Every adapter author
 * (Prisma/pg/Drizzle/whatever) MUST run this against their REAL backing
 * store before trusting it.
 *
 * *** Passing this suite against `createMemoryRefreshTokenStore()` proves
 * NOTHING about a real adapter's atomicity. *** The in-memory store's
 * `rotate()` is `async` but awaits nothing, so under Node's run-to-completion
 * semantics it is atomic "for free" — every property below holds even with
 * ZERO locking, because JavaScript is single-threaded, not because the
 * algorithm is sound. A real database can — and on Postgres at READ
 * COMMITTED, WILL — let two concurrent `rotate()` calls on the same token
 * both "win" (a classic lost update) unless the adapter's transaction uses
 * `SELECT ... FOR UPDATE` (or an equivalent atomic compare-and-swap, e.g. a
 * conditional `UPDATE ... WHERE revoked_at IS NULL RETURNING *`) around the
 * whole decide-and-act sequence documented on {@link RefreshTokenStore.rotate}.
 *
 * Usage, from the adapter package's own vitest (or Jest) test file:
 *
 * ```ts
 * import { describe, it, expect } from 'vitest';
 * import { runRefreshTokenStoreConformanceTests } from '@andrewpopov/auth-kit/conformance';
 * import { createMyPostgresStore } from '../src/postgres-store';
 *
 * runRefreshTokenStoreConformanceTests(() => createMyPostgresStore(testDb), { describe, it, expect });
 * ```
 */
export function runRefreshTokenStoreConformanceTests(
  makeStore: () => RefreshTokenStore | Promise<RefreshTokenStore>,
  harness: ConformanceTestHarness,
  options?: { concurrency?: number },
): void {
  const { describe, it, expect } = harness;
  const concurrency = options?.concurrency ?? 20;

  describe('RefreshTokenStore conformance', () => {
    it('createSession + findByHash: stores only the hash, never the raw token', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const row = await store.findByHash(hashOpaqueToken(issued.rawToken));
      expect(row).not.toBeNull();
      expect(row!.tokenHash).toBe(hashOpaqueToken(issued.rawToken));
      expect(JSON.stringify(row)).not.toContain(issued.rawToken);
    });

    it('rotate(): an unknown token hash -> not-found (mapped to `invalid`)', async () => {
      const store = await makeStore();
      const result = await rotateRefreshToken(store, 'not-a-real-token', TTL_MS);
      expect(result.outcome).toBe('invalid');
    });

    it('rotate(): an expired, never-rotated token -> expired (mapped to `invalid`), not reuse', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', 1, { now: new Date(1_000) });
      const result = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { now: new Date(1_002) });
      expect(result.outcome).toBe('invalid');
    });

    it(
      'rotate(): single-use under GENUINE concurrency — N parallel rotate() calls on the same token, exactly one succeeds ' +
        '(this is the assertion a naive read-then-write adapter fails under real concurrent connections, even though it ' +
        'passes trivially against the in-memory store)',
      async () => {
        const store = await makeStore();
        const issued = await createRefreshToken(store, 'user-1', TTL_MS);
        const oldHash = hashOpaqueToken(issued.rawToken);

        const attempts = Array.from({ length: concurrency }, () =>
          store.rotate(
            oldHash,
            { id: crypto.randomUUID(), tokenHash: hashOpaqueToken(generateOpaqueToken()), expiresAt: new Date(Date.now() + TTL_MS) },
            { graceMs: 0, now: new Date() },
          ),
        );
        const results = await Promise.all(attempts);
        const rotatedCount = results.filter((r) => r.status === 'rotated').length;
        expect(rotatedCount).toBe(1);
      },
    );

    it('rotate(): replaying an already-rotated token OUTSIDE the grace window revokes the whole family, including the legitimate successor', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const rotated = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
      expect(rotated.outcome).toBe('rotated');
      if (rotated.outcome !== 'rotated') throw new Error('unreachable');

      const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: 0 });
      expect(replay.outcome).toBe('reuse');

      const successorAttempt = await rotateRefreshToken(store, rotated.rawToken, TTL_MS);
      expect(successorAttempt.outcome).toBe('reuse');
    });

    it('rotate(): graceMs defaults to DEFAULT_ROTATION_GRACE_MS — a replay within the default window (no graceMs passed) is benign, not reuse', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS); // no graceMs passed
      expect(winner.outcome).toBe('rotated');

      const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS); // no graceMs passed
      expect(replay.outcome).toBe('rotated');
    });

    it('rotate(): graceMs defaults to DEFAULT_ROTATION_GRACE_MS — a replay outside the default window (no graceMs passed) is still reuse', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const t0 = new Date();
      const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { now: t0 }); // no graceMs passed
      expect(winner.outcome).toBe('rotated');

      const afterWindow = new Date(t0.getTime() + DEFAULT_ROTATION_GRACE_MS + 1);
      const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { now: afterWindow }); // no graceMs passed
      expect(replay.outcome).toBe('reuse');
    });

    it('rotate(): within an explicitly opted-in grace window, with an active replacement -> benign race, family survives', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS });
      expect(winner.outcome).toBe('rotated');
      if (winner.outcome !== 'rotated') throw new Error('unreachable');

      const loser = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS });
      expect(loser.outcome).toBe('rotated');
      if (loser.outcome !== 'rotated') throw new Error('unreachable');
      expect(loser.familyId).toBe(winner.familyId);
      expect(loser.rawToken).not.toBe(winner.rawToken);

      expect((await rotateRefreshToken(store, winner.rawToken, TTL_MS)).outcome).toBe('rotated');
      expect((await rotateRefreshToken(store, loser.rawToken, TTL_MS)).outcome).toBe('rotated');
    });

    it('revokeFamily: kills every active session in the family, and is idempotent', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      await store.revokeFamily(issued.familyId);
      const attempt = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
      expect(attempt.outcome).toBe('reuse');
      await expect(store.revokeFamily(issued.familyId)).resolves.toBeUndefined();
    });

    it('revokeAllForUser: kills every family for the user, leaves other users untouched', async () => {
      const store = await makeStore();
      const a = await createRefreshToken(store, 'user-1', TTL_MS);
      const b = await createRefreshToken(store, 'user-1', TTL_MS);
      const other = await createRefreshToken(store, 'user-2', TTL_MS);
      await store.revokeAllForUser('user-1');
      expect((await rotateRefreshToken(store, a.rawToken, TTL_MS)).outcome).toBe('reuse');
      expect((await rotateRefreshToken(store, b.rawToken, TTL_MS)).outcome).toBe('reuse');
      expect((await rotateRefreshToken(store, other.rawToken, TTL_MS)).outcome).toBe('rotated');
    });

    it('bumpEpoch: strictly monotonic even for back-to-back bumps', async () => {
      const store = await makeStore();
      const first = await store.bumpEpoch('user-1');
      const second = await store.bumpEpoch('user-1');
      expect(second.getTime()).toBeGreaterThan(first.getTime());
    });

    it(
      'Defect-A regression: a family revoked concurrently with a benign-race replay never leaves a live token in that family ' +
        '(the property the 0.2.0 two-call design violated — see CHANGELOG "0.2.1 — BREAKING")',
      async () => {
        const store = await makeStore();
        const issued = await createRefreshToken(store, 'user-1', TTL_MS);
        const rotated = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
        expect(rotated.outcome).toBe('rotated');
        if (rotated.outcome !== 'rotated') throw new Error('unreachable');

        const [replay] = await Promise.all([
          rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS }),
          store.revokeFamily(rotated.familyId),
        ]);

        if (replay.outcome === 'rotated') {
          const row = await store.findByHash(hashOpaqueToken(replay.rawToken));
          expect(row).not.toBeNull();
          expect(row!.revokedAt).not.toBeNull();
        } else {
          expect(replay.outcome).toBe('reuse');
        }
      },
    );
  });
}

/**
 * ExternalIdentityStore PORT CONFORMANCE SUITE. Unlike refresh sessions, this
 * protocol spans two unique namespaces: local account ids and (issuer,
 * subject). `bindExternalIdentity` and `claimPlaceholder` must decide and act
 * atomically — a select followed by an unconditional update permits two
 * accounts to win the same Google subject under real database concurrency.
 *
 * Consumers provide a test-only preparation adapter because account schemas
 * differ. It must insert exactly the supplied account attributes into the real
 * database; no fake in-memory store proves database uniqueness or CAS safety.
 */
export function runExternalIdentityStoreConformanceTests(
  makeStore: () => ExternalIdentityStore | Promise<ExternalIdentityStore>,
  prepare: (store: ExternalIdentityStore) => IdentityStoreConformancePreparation | Promise<IdentityStoreConformancePreparation>,
  harness: ConformanceTestHarness,
  options?: { concurrency?: number },
): void {
  const { describe, it, expect } = harness;
  const concurrency = options?.concurrency ?? 20;

  describe('ExternalIdentityStore conformance', () => {
    it('resolves a returning identity by issuer + subject, not email', async () => {
      const store = await makeStore();
      const fixture = await prepare(store);
      await fixture.createAccount({ id: 'identity-returning', email: 'old@example.test', emailVerified: true, disabled: false, hasCredentials: true });
      expect((await store.bindExternalIdentity('identity-returning', conformanceIdentity)).status).toBe('linked');
      const result = await resolveExternalIdentity(store, conformancePolicy, { ...conformanceIdentity, email: 'changed@example.test' });
      expect(result).toMatchObject({ outcome: 'returning', account: { id: 'identity-returning' } });
    });

    it('never adopts a credentialed matching-email account from an unauthenticated callback', async () => {
      const store = await makeStore();
      const fixture = await prepare(store);
      await fixture.createAccount({ id: 'identity-credentialed', email: conformanceIdentity.email, emailVerified: true, disabled: false, hasCredentials: true });
      const result = await resolveExternalIdentity(store, conformancePolicy, conformanceIdentity);
      expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'identity-credentialed' } });
      expect(await store.findAccountByExternalIdentity(conformanceIdentity)).toBeNull();
    });

    it('claims only an unverified, uncredentialed matching-email placeholder', async () => {
      const store = await makeStore();
      const fixture = await prepare(store);
      await fixture.createAccount({ id: 'identity-placeholder', email: conformanceIdentity.email, emailVerified: false, disabled: false, hasCredentials: false });
      const result = await resolveExternalIdentity(store, conformancePolicy, conformanceIdentity);
      expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'identity-placeholder' } });
    });

    it('canaries subject uniqueness under real concurrency: exactly one account links the same identity', async () => {
      const store = await makeStore();
      const fixture = await prepare(store);
      await Promise.all(Array.from({ length: concurrency }, (_, index) =>
        fixture.createAccount({ id: `identity-race-${index}`, email: `identity-race-${index}@example.test`, emailVerified: true, disabled: false, hasCredentials: true }),
      ));
      const attempts = await Promise.all(Array.from({ length: concurrency }, (_, index) =>
        linkExternalIdentity(store, conformancePolicy, `identity-race-${index}`, { ...conformanceIdentity, email: `identity-race-${index}@example.test` }),
      ));
      const linked = attempts.filter(result => result.outcome === 'linked').length;
      expect(linked).toBe(1);
      const owner = await store.findAccountByExternalIdentity(conformanceIdentity);
      expect(owner).not.toBeNull();
    });
  });
}
