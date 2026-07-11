import crypto from 'crypto';
import {
  createRefreshToken,
  rotateRefreshToken,
  hashOpaqueToken,
  generateOpaqueToken,
  DEFAULT_ROTATION_GRACE_MS,
  type RefreshTokenStore,
} from './index';

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** The subset of `expect(...)`'s chainable API this suite uses — structurally satisfied by vitest's and Jest's `expect` (both are duck-typed, not imported). */
export interface ExpectLike {
  (actual: unknown): {
    toBe(expected: unknown): void;
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
      const issued = await createRefreshToken(store, 'user-1', -1);
      const result = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
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

    it('rotate(): graceMs defaults to 0 — a replay outside an explicitly-configured window is reuse, not benign', async () => {
      const store = await makeStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS); // no graceMs passed
      expect(winner.outcome).toBe('rotated');

      const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS); // no graceMs passed
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
