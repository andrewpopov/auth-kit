import { type AccountIdentityRecord, type ExternalIdentityStore, type RefreshTokenStore } from './index';
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
export declare function runRefreshTokenStoreConformanceTests(makeStore: () => RefreshTokenStore | Promise<RefreshTokenStore>, harness: ConformanceTestHarness, options?: {
    concurrency?: number;
}): void;
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
export declare function runExternalIdentityStoreConformanceTests(makeStore: () => ExternalIdentityStore | Promise<ExternalIdentityStore>, prepare: (store: ExternalIdentityStore) => IdentityStoreConformancePreparation | Promise<IdentityStoreConformancePreparation>, harness: ConformanceTestHarness, options?: {
    concurrency?: number;
    raceRepeats?: number;
}): void;
