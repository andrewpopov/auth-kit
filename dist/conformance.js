"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runRefreshTokenStoreConformanceTests = runRefreshTokenStoreConformanceTests;
exports.runExternalIdentityStoreConformanceTests = runExternalIdentityStoreConformanceTests;
exports.runSingleUseTokenStoreConformanceTests = runSingleUseTokenStoreConformanceTests;
const crypto_1 = __importDefault(require("crypto"));
const index_1 = require("./index");
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const conformanceIdentity = {
    issuer: 'https://accounts.google.com',
    subject: 'auth-kit-conformance-subject',
    email: 'identity-conformance@example.test',
    emailAuthority: 'hosted',
};
const conformancePolicy = {
    mayProvision: () => true,
    mayClaimPlaceholder: () => true,
};
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
function runRefreshTokenStoreConformanceTests(makeStore, harness, options) {
    const { describe, it, expect } = harness;
    const concurrency = options?.concurrency ?? 20;
    describe('RefreshTokenStore conformance', () => {
        it('createSession + findByHash: stores only the hash, never the raw token', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const row = await store.findByHash((0, index_1.hashOpaqueToken)(issued.rawToken));
            expect(row).not.toBeNull();
            expect(row.tokenHash).toBe((0, index_1.hashOpaqueToken)(issued.rawToken));
            expect(JSON.stringify(row)).not.toContain(issued.rawToken);
        });
        it('rotate(): an unknown token hash -> not-found (mapped to `invalid`)', async () => {
            const store = await makeStore();
            const result = await (0, index_1.rotateRefreshToken)(store, 'not-a-real-token', TTL_MS);
            expect(result.outcome).toBe('invalid');
        });
        it('rotate(): an expired, never-rotated token -> expired (mapped to `invalid`), not reuse', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', 1, { now: new Date(1000) });
            const result = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { now: new Date(1002) });
            expect(result.outcome).toBe('invalid');
        });
        it('rotate(): single-use under GENUINE concurrency — N parallel rotate() calls on the same token, exactly one succeeds ' +
            '(this is the assertion a naive read-then-write adapter fails under real concurrent connections, even though it ' +
            'passes trivially against the in-memory store)', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const oldHash = (0, index_1.hashOpaqueToken)(issued.rawToken);
            const attempts = Array.from({ length: concurrency }, () => store.rotate(oldHash, { id: crypto_1.default.randomUUID(), tokenHash: (0, index_1.hashOpaqueToken)((0, index_1.generateOpaqueToken)()), expiresAt: new Date(Date.now() + TTL_MS) }, { graceMs: 0, now: new Date() }));
            const results = await Promise.all(attempts);
            const rotatedCount = results.filter((r) => r.status === 'rotated').length;
            expect(rotatedCount).toBe(1);
        });
        it('rotate(): replaying an already-rotated token OUTSIDE the grace window revokes the whole family, including the legitimate successor', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const rotated = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS);
            expect(rotated.outcome).toBe('rotated');
            if (rotated.outcome !== 'rotated')
                throw new Error('unreachable');
            const replay = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { graceMs: 0 });
            expect(replay.outcome).toBe('reuse');
            const successorAttempt = await (0, index_1.rotateRefreshToken)(store, rotated.rawToken, TTL_MS);
            expect(successorAttempt.outcome).toBe('reuse');
        });
        it('rotate(): graceMs defaults to DEFAULT_ROTATION_GRACE_MS — a replay within the default window (no graceMs passed) is benign, not reuse', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const winner = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS); // no graceMs passed
            expect(winner.outcome).toBe('rotated');
            const replay = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS); // no graceMs passed
            expect(replay.outcome).toBe('rotated');
        });
        it('rotate(): the default window is inclusive — a replay at exactly DEFAULT_ROTATION_GRACE_MS is still benign', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const t0 = new Date();
            const winner = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { now: t0 }); // no graceMs passed
            expect(winner.outcome).toBe('rotated');
            const atBoundary = new Date(t0.getTime() + index_1.DEFAULT_ROTATION_GRACE_MS);
            const replay = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { now: atBoundary }); // no graceMs passed
            expect(replay.outcome).toBe('rotated');
        });
        it('rotate(): graceMs defaults to DEFAULT_ROTATION_GRACE_MS — a replay outside the default window (no graceMs passed) is still reuse', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const t0 = new Date();
            const winner = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { now: t0 }); // no graceMs passed
            expect(winner.outcome).toBe('rotated');
            const afterWindow = new Date(t0.getTime() + index_1.DEFAULT_ROTATION_GRACE_MS + 1);
            const replay = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { now: afterWindow }); // no graceMs passed
            expect(replay.outcome).toBe('reuse');
        });
        it('rotate(): within an explicitly opted-in grace window, with an active replacement -> benign race, family survives', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const winner = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { graceMs: index_1.DEFAULT_ROTATION_GRACE_MS });
            expect(winner.outcome).toBe('rotated');
            if (winner.outcome !== 'rotated')
                throw new Error('unreachable');
            const loser = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { graceMs: index_1.DEFAULT_ROTATION_GRACE_MS });
            expect(loser.outcome).toBe('rotated');
            if (loser.outcome !== 'rotated')
                throw new Error('unreachable');
            expect(loser.familyId).toBe(winner.familyId);
            expect(loser.rawToken).not.toBe(winner.rawToken);
            expect((await (0, index_1.rotateRefreshToken)(store, winner.rawToken, TTL_MS)).outcome).toBe('rotated');
            expect((await (0, index_1.rotateRefreshToken)(store, loser.rawToken, TTL_MS)).outcome).toBe('rotated');
        });
        it('revokeFamily: kills every active session in the family, and is idempotent', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            await store.revokeFamily(issued.familyId);
            const attempt = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS);
            expect(attempt.outcome).toBe('reuse');
            await expect(store.revokeFamily(issued.familyId)).resolves.toBeUndefined();
        });
        it('revokeAllForUser: kills every family for the user, leaves other users untouched', async () => {
            const store = await makeStore();
            const a = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const b = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const other = await (0, index_1.createRefreshToken)(store, 'user-2', TTL_MS);
            await store.revokeAllForUser('user-1');
            expect((await (0, index_1.rotateRefreshToken)(store, a.rawToken, TTL_MS)).outcome).toBe('reuse');
            expect((await (0, index_1.rotateRefreshToken)(store, b.rawToken, TTL_MS)).outcome).toBe('reuse');
            expect((await (0, index_1.rotateRefreshToken)(store, other.rawToken, TTL_MS)).outcome).toBe('rotated');
        });
        it('bumpEpoch: strictly monotonic even for back-to-back bumps', async () => {
            const store = await makeStore();
            const first = await store.bumpEpoch('user-1');
            const second = await store.bumpEpoch('user-1');
            expect(second.getTime()).toBeGreaterThan(first.getTime());
        });
        it('Defect-A regression: a family revoked concurrently with a benign-race replay never leaves a live token in that family ' +
            '(the property the 0.2.0 two-call design violated — see CHANGELOG "0.2.1 — BREAKING")', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.createRefreshToken)(store, 'user-1', TTL_MS);
            const rotated = await (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS);
            expect(rotated.outcome).toBe('rotated');
            if (rotated.outcome !== 'rotated')
                throw new Error('unreachable');
            const [replay] = await Promise.all([
                (0, index_1.rotateRefreshToken)(store, issued.rawToken, TTL_MS, { graceMs: index_1.DEFAULT_ROTATION_GRACE_MS }),
                store.revokeFamily(rotated.familyId),
            ]);
            if (replay.outcome === 'rotated') {
                const row = await store.findByHash((0, index_1.hashOpaqueToken)(replay.rawToken));
                expect(row).not.toBeNull();
                expect(row.revokedAt).not.toBeNull();
            }
            else {
                expect(replay.outcome).toBe('reuse');
            }
        });
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
function runExternalIdentityStoreConformanceTests(makeStore, prepare, harness, options) {
    const { describe, it, expect } = harness;
    const concurrency = options?.concurrency ?? 20;
    // Used by the placeholder-claim race below. `Promise.all` gives GENUINE
    // concurrency (real overlapping I/O against a real adapter) but no barrier
    // between an adapter's internal read and write phases, so a non-atomic
    // adapter can still pass a single round by scheduling luck (e.g. a
    // connection pool that happens to serialize the calls). Repeating the race
    // over fresh state makes a lucky pass across every round unlikely, not
    // impossible — this is a PROBABILISTIC canary, not a proof of atomicity.
    const raceRepeats = options?.raceRepeats ?? 5;
    describe('ExternalIdentityStore conformance', () => {
        it('resolves a returning identity by issuer + subject, not email', async () => {
            const store = await makeStore();
            const fixture = await prepare(store);
            await fixture.createAccount({ id: 'identity-returning', email: 'old@example.test', emailVerified: true, disabled: false, hasCredentials: true });
            expect((await store.bindExternalIdentity('identity-returning', conformanceIdentity)).status).toBe('linked');
            const result = await (0, index_1.resolveExternalIdentity)(store, conformancePolicy, { ...conformanceIdentity, email: 'changed@example.test' });
            expect(result).toMatchObject({ outcome: 'returning', account: { id: 'identity-returning' } });
        });
        it('never adopts a credentialed matching-email account from an unauthenticated callback', async () => {
            const store = await makeStore();
            const fixture = await prepare(store);
            await fixture.createAccount({ id: 'identity-credentialed', email: conformanceIdentity.email, emailVerified: true, disabled: false, hasCredentials: true });
            const result = await (0, index_1.resolveExternalIdentity)(store, conformancePolicy, conformanceIdentity);
            expect(result).toMatchObject({ outcome: 'account-exists', account: { id: 'identity-credentialed' } });
            expect(await store.findAccountByExternalIdentity(conformanceIdentity)).toBeNull();
        });
        it('claims only an unverified, uncredentialed matching-email placeholder', async () => {
            const store = await makeStore();
            const fixture = await prepare(store);
            await fixture.createAccount({ id: 'identity-placeholder', email: conformanceIdentity.email, emailVerified: false, disabled: false, hasCredentials: false });
            const result = await (0, index_1.resolveExternalIdentity)(store, conformancePolicy, conformanceIdentity);
            expect(result).toMatchObject({ outcome: 'claimed-placeholder', account: { id: 'identity-placeholder' } });
        });
        it('canaries subject uniqueness under real concurrency: exactly one account links the same identity', async () => {
            const store = await makeStore();
            const fixture = await prepare(store);
            await Promise.all(Array.from({ length: concurrency }, (_, index) => fixture.createAccount({ id: `identity-race-${index}`, email: `identity-race-${index}@example.test`, emailVerified: true, disabled: false, hasCredentials: true })));
            const attempts = await Promise.all(Array.from({ length: concurrency }, (_, index) => (0, index_1.linkExternalIdentity)(store, conformancePolicy, `identity-race-${index}`, { ...conformanceIdentity, email: `identity-race-${index}@example.test` })));
            const linked = attempts.filter(result => result.outcome === 'linked').length;
            expect(linked).toBe(1);
            const owner = await store.findAccountByExternalIdentity(conformanceIdentity);
            expect(owner).not.toBeNull();
        });
        it(`claimPlaceholder single-use under real concurrency, repeated ${raceRepeats}x over fresh placeholders: N parallel ` +
            'claimPlaceholder() calls on the SAME placeholder, exactly one succeeds each round (mirrors the bind-race canary ' +
            'above, but for claimPlaceholder — a select-then-update claimPlaceholder can let two concurrent callers both ' +
            '"win" the same placeholder). Deliberately races ONE placeholder per round, not several sharing an email — ' +
            'several placeholders with the same normalized email would spuriously fail against an otherwise-conforming ' +
            'adapter that enforces email uniqueness, which is worse than the atomicity gap this canary exists to catch. ' +
            'PROBABILISTIC, like the concurrency canary above: a genuinely non-atomic adapter could still pass any single ' +
            'round by scheduling luck (Promise.all provides concurrency, not a read/write barrier) — repeating over fresh ' +
            'placeholders makes that unlikely across every round, not impossible.', async () => {
            const store = await makeStore();
            const fixture = await prepare(store);
            for (let round = 0; round < raceRepeats; round++) {
                const id = `identity-claim-race-${round}`;
                const roundIdentity = {
                    ...conformanceIdentity,
                    subject: `${conformanceIdentity.subject}-claim-race-${round}`,
                    email: `identity-claim-race-${round}@example.test`,
                };
                await fixture.createAccount({ id, email: roundIdentity.email, emailVerified: false, disabled: false, hasCredentials: false });
                const attempts = await Promise.all(Array.from({ length: concurrency }, () => store.claimPlaceholder(id, roundIdentity)));
                expect(attempts.filter(result => result.status === 'claimed').length).toBe(1);
                // Re-read the account rather than trust the return values alone:
                // the mutation must have actually landed exactly once.
                const finalAccount = await store.findAccountById(id);
                expect(finalAccount).not.toBeNull();
                expect(finalAccount.emailVerified).toBe(true);
            }
        });
    });
}
const SINGLE_USE_TTL_MS = 15 * 60 * 1000; // a typical password-reset window
/**
 * SingleUseTokenStore PORT CONFORMANCE SUITE. Every adapter author
 * (Prisma/pg/Drizzle/whatever) MUST run this against their REAL backing
 * store before trusting it.
 *
 * *** Passing this suite against `createMemorySingleUseTokenStore()` proves
 * NOTHING about a real adapter's atomicity. *** The in-memory store's
 * `consume()` is `async` but awaits nothing, so under Node's run-to-completion
 * semantics it is atomic "for free" — every property below holds even with
 * ZERO locking, because JavaScript is single-threaded, not because the
 * algorithm is sound. A real database can — and on Postgres at READ
 * COMMITTED, WILL — let two concurrent `consume()` calls on the same hash
 * both "win" (a classic lost update) unless the adapter's transaction uses
 * `SELECT ... FOR UPDATE` (or an equivalent atomic compare-and-swap, e.g. a
 * conditional `UPDATE ... WHERE token_hash = $h AND purpose = $p AND
 * consumed_at IS NULL AND expires_at > $now RETURNING *`) around the whole
 * decide-and-act sequence documented on {@link SingleUseTokenStore.consume}.
 *
 * Usage, from the adapter package's own vitest (or Jest) test file:
 *
 * ```ts
 * import { describe, it, expect } from 'vitest';
 * import { runSingleUseTokenStoreConformanceTests } from '@andrewpopov/auth-kit/conformance';
 * import { createMyPostgresStore } from '../src/postgres-store';
 *
 * runSingleUseTokenStoreConformanceTests(() => createMyPostgresStore(testDb), { describe, it, expect });
 * ```
 */
function runSingleUseTokenStoreConformanceTests(makeStore, harness, options) {
    const { describe, it, expect } = harness;
    const concurrency = options?.concurrency ?? 20;
    // Used by both race cases below. `Promise.all` gives GENUINE concurrency
    // (real overlapping I/O against a real adapter) but no barrier between an
    // adapter's internal read and write phases, so a non-atomic adapter can
    // still pass a single round by scheduling luck (e.g. a connection pool
    // that happens to serialize the calls). Repeating the race over fresh
    // state makes a lucky pass across every round unlikely, not impossible —
    // this is a PROBABILISTIC canary, not a proof of atomicity.
    const raceRepeats = options?.raceRepeats ?? 5;
    if (!Number.isInteger(concurrency) || concurrency < 2) {
        throw new Error(`runSingleUseTokenStoreConformanceTests: concurrency must be an integer >= 2 (got ${concurrency}) — a suite run ` +
            'with concurrency 1 (or a non-finite value like NaN, which passes a bare `< 2` check) would "pass" while ' +
            'testing nothing, which is worse than not running it.');
    }
    if (!Number.isInteger(raceRepeats) || raceRepeats < 1) {
        throw new Error(`runSingleUseTokenStoreConformanceTests: raceRepeats must be an integer >= 1 (got ${raceRepeats}) — a suite run ` +
            'with raceRepeats 0 (or a non-finite value like NaN, which passes a bare `< 1` check) would register the race ' +
            'case but run zero rounds of it, passing vacuously, which is worse than not running it.');
    }
    describe('SingleUseTokenStore conformance', () => {
        it('happy path: redeems, with the issued purpose/subjectId and consumedAt === now on the record', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId: 'user-1', ttlMs: SINGLE_USE_TTL_MS });
            const now = new Date();
            const result = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset', now });
            expect(result.outcome).toBe('redeemed');
            if (result.outcome !== 'redeemed')
                throw new Error('unreachable');
            expect(result.record.purpose).toBe('password-reset');
            expect(result.record.subjectId).toBe('user-1');
            expect(result.record.consumedAt).toEqual(now);
        });
        it('redeemSingleUseToken(): an unknown token hash -> invalid', async () => {
            const store = await makeStore();
            const result = await (0, index_1.redeemSingleUseToken)(store, 'not-a-real-token', { purpose: 'password-reset' });
            expect(result.outcome).toBe('invalid');
        });
        it('sequential replay of the same token -> already-consumed, not redeemed again', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId: 'user-1', ttlMs: SINGLE_USE_TTL_MS });
            const first = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset' });
            expect(first.outcome).toBe('redeemed');
            const second = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset' });
            expect(second.outcome).toBe('already-consumed');
        });
        it(`consume(): single-use under GENUINE concurrency, repeated ${raceRepeats}x over fresh tokens — N parallel ` +
            'store.consume() calls on the SAME token hash, asserting exactly one `consumed` AND exactly N-1 ' +
            '`already-consumed` each round (counting winners alone would let an adapter that reports losers as ' +
            '`not-found`/`expired` slip past this suite). This is the assertion a naive read-then-write adapter fails ' +
            'under real concurrent connections, even though it passes trivially against the in-memory store. ' +
            'PROBABILISTIC, like the identity suite\'s placeholder-claim canary: Promise.all provides concurrency, not ' +
            'a read/write barrier, so a genuinely non-atomic adapter could still pass any single round by scheduling ' +
            'luck — repeating over fresh tokens makes that unlikely across every round, not impossible.', async () => {
            const store = await makeStore();
            for (let round = 0; round < raceRepeats; round++) {
                const issued = await (0, index_1.issueSingleUseToken)(store, {
                    purpose: 'password-reset',
                    subjectId: `user-consume-race-${round}`,
                    ttlMs: SINGLE_USE_TTL_MS,
                });
                const tokenHash = (0, index_1.hashOpaqueToken)(issued.rawToken);
                const attempts = await Promise.all(Array.from({ length: concurrency }, () => store.consume(tokenHash, { purpose: 'password-reset', now: new Date() })));
                const consumedCount = attempts.filter(result => result.status === 'consumed').length;
                const alreadyConsumedCount = attempts.filter(result => result.status === 'already-consumed').length;
                expect(consumedCount).toBe(1);
                expect(alreadyConsumedCount).toBe(concurrency - 1);
            }
        });
        it('invalidateAllFor() resolving BEFORE consume() is called: DETERMINISTIC, no ordering ambiguity — once ' +
            'invalidateAllFor() has fully resolved, the linearization requirement (its commit is the linearization ' +
            'point — see {@link SingleUseTokenStore.consume}) is completely observable through this port, so a ' +
            'subsequent consume() on a token it covered MUST report `already-consumed`, never `consumed`. This is the ' +
            'case a non-atomic read-then-write consume() (one that already read the row before invalidateAllFor() ' +
            'committed, in the SAME call) cannot be caught by directly — see the concurrent variant below for that.', async () => {
            const store = await makeStore();
            const subjectId = 'user-invalidate-then-consume';
            const issued = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId, ttlMs: SINGLE_USE_TTL_MS });
            const tokenHash = (0, index_1.hashOpaqueToken)(issued.rawToken);
            await store.invalidateAllFor(subjectId, 'password-reset');
            const result = await store.consume(tokenHash, { purpose: 'password-reset', now: new Date() });
            expect(result.status).toBe('already-consumed');
        });
        it(`consume() racing invalidateAllFor() on the same subject+purpose, repeated ${raceRepeats}x over fresh tokens — ` +
            'a SMOKE TEST that the two operations do not corrupt each other under real concurrent I/O. This is NOT a ' +
            'linearization proof: through this port there is no way to observe which of the two committed first, so a ' +
            'consume() that reads the row before invalidateAllFor() commits and then WRITES after it commits — the exact ' +
            'linearization violation the contract forbids — is indistinguishable here from a legitimate win, because ' +
            '`raceResult.status === \'consumed\'` is accepted either way. A real proof would need an adapter ' +
            'synchronization hook (a way to pause a transaction mid-flight so the test can force the interleaving) that ' +
            'this port does not expose; the deterministic case above is what actually gates that violation. What this ' +
            'case DOES assert: both calls resolve without throwing, and the store is left internally consistent ' +
            'afterward (a follow-up consume() reports a well-formed status, `consumed` or `already-consumed`, not a ' +
            'result the token retirement makes impossible).', async () => {
            const store = await makeStore();
            for (let round = 0; round < raceRepeats; round++) {
                const subjectId = `user-invalidate-race-${round}`;
                const issued = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId, ttlMs: SINGLE_USE_TTL_MS });
                const tokenHash = (0, index_1.hashOpaqueToken)(issued.rawToken);
                const [raceResult] = await Promise.all([
                    store.consume(tokenHash, { purpose: 'password-reset', now: new Date() }),
                    store.invalidateAllFor(subjectId, 'password-reset'),
                ]);
                expect(['consumed', 'already-consumed']).toContain(raceResult.status);
                const after = await store.consume(tokenHash, { purpose: 'password-reset', now: new Date() });
                expect(after.status).toBe('already-consumed');
            }
        });
        it('expiry is decided INSIDE the atomic consume(): a token past expiresAt -> expired, and advancing time keeps it expired', async () => {
            const store = await makeStore();
            const issuedAt = new Date('2026-01-01T00:00:00.000Z');
            const issued = await (0, index_1.issueSingleUseToken)(store, {
                purpose: 'password-reset',
                subjectId: 'user-1',
                ttlMs: SINGLE_USE_TTL_MS,
                now: issuedAt,
            });
            const afterExpiry = new Date(issued.expiresAt.getTime() + 1);
            const first = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset', now: afterExpiry });
            expect(first.outcome).toBe('expired');
            // Expiry must not have consumed the token (nothing written) — but it
            // must ALSO never become redeemable again as real time keeps advancing.
            const later = new Date(issued.expiresAt.getTime() + 10000);
            const second = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset', now: later });
            expect(second.outcome).toBe('expired');
        });
        it('the expiry boundary is inclusive: consuming at exactly now === expiresAt -> expired', async () => {
            const store = await makeStore();
            const issuedAt = new Date('2026-01-01T00:00:00.000Z');
            const issued = await (0, index_1.issueSingleUseToken)(store, {
                purpose: 'password-reset',
                subjectId: 'user-1',
                ttlMs: SINGLE_USE_TTL_MS,
                now: issuedAt,
            });
            const atExpiry = new Date(issued.expiresAt.getTime());
            const result = await (0, index_1.redeemSingleUseToken)(store, issued.rawToken, { purpose: 'password-reset', now: atExpiry });
            expect(result.outcome).toBe('expired');
        });
        it('purpose isolation: consuming under the wrong purpose -> purpose-mismatch with nothing written, proven by the token still consuming under its real purpose afterwards', async () => {
            const store = await makeStore();
            const issued = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId: 'user-1', ttlMs: SINGLE_USE_TTL_MS });
            const tokenHash = (0, index_1.hashOpaqueToken)(issued.rawToken);
            const wrongPurpose = await store.consume(tokenHash, { purpose: 'invite', now: new Date() });
            expect(wrongPurpose.status).toBe('purpose-mismatch');
            // Nothing was written — the token still consumes under its real purpose.
            const realPurpose = await store.consume(tokenHash, { purpose: 'password-reset', now: new Date() });
            expect(realPurpose.status).toBe('consumed');
        });
        it('invalidateAllFor(): retires outstanding tokens for that subject+purpose only, leaves other subjects/purposes redeemable, is idempotent, and a retired token reads already-consumed (never not-found)', async () => {
            const store = await makeStore();
            const target = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId: 'user-1', ttlMs: SINGLE_USE_TTL_MS });
            const otherSubject = await (0, index_1.issueSingleUseToken)(store, { purpose: 'password-reset', subjectId: 'user-2', ttlMs: SINGLE_USE_TTL_MS });
            const otherPurpose = await (0, index_1.issueSingleUseToken)(store, { purpose: 'invite', subjectId: 'user-1', ttlMs: SINGLE_USE_TTL_MS });
            await store.invalidateAllFor('user-1', 'password-reset');
            await expect(store.invalidateAllFor('user-1', 'password-reset')).resolves.toBeUndefined(); // idempotent — must not throw or double-act
            const targetResult = await store.consume((0, index_1.hashOpaqueToken)(target.rawToken), { purpose: 'password-reset', now: new Date() });
            expect(targetResult.status).toBe('already-consumed'); // not-found would betray deletion
            const otherSubjectResult = await store.consume((0, index_1.hashOpaqueToken)(otherSubject.rawToken), { purpose: 'password-reset', now: new Date() });
            expect(otherSubjectResult.status).toBe('consumed');
            const otherPurposeResult = await store.consume((0, index_1.hashOpaqueToken)(otherPurpose.rawToken), { purpose: 'invite', now: new Date() });
            expect(otherPurposeResult.status).toBe('consumed');
        });
        it('issue(): rejects a duplicate tokenHash', async () => {
            const store = await makeStore();
            const record = {
                id: crypto_1.default.randomUUID(),
                purpose: 'password-reset',
                subjectId: 'user-1',
                tokenHash: (0, index_1.hashOpaqueToken)((0, index_1.generateOpaqueToken)()),
                expiresAt: new Date(Date.now() + SINGLE_USE_TTL_MS),
                consumedAt: null,
            };
            await store.issue(record);
            await expect(store.issue({ ...record, id: crypto_1.default.randomUUID() })).rejects.toThrow();
        });
        it(`issue(): tokenHash uniqueness under GENUINE concurrency — issuing the SAME tokenHash from ${concurrency} ` +
            'parallel callers, exactly one succeeds and the rest reject. The sequential duplicate-tokenHash case above ' +
            'cannot catch a non-atomic check-then-insert adapter: it can let two rows share a tokenHash when the checks ' +
            'race, and the uniqueness invariant exists precisely so that never happens — two rows sharing a hash would ' +
            'let two concurrent consume() calls each win a DIFFERENT row, the exact double-redeem the whole ' +
            'consume()-atomicity contract is meant to prevent.', async () => {
            const store = await makeStore();
            const tokenHash = (0, index_1.hashOpaqueToken)((0, index_1.generateOpaqueToken)());
            const attempts = await Promise.allSettled(Array.from({ length: concurrency }, () => store.issue({
                id: crypto_1.default.randomUUID(),
                purpose: 'password-reset',
                subjectId: 'user-issue-race',
                tokenHash,
                expiresAt: new Date(Date.now() + SINGLE_USE_TTL_MS),
                consumedAt: null,
            })));
            const succeeded = attempts.filter((result) => result.status === 'fulfilled').length;
            expect(succeeded).toBe(1);
        });
    });
}
