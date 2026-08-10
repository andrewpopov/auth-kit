"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueSingleUseToken = issueSingleUseToken;
exports.redeemSingleUseToken = redeemSingleUseToken;
exports.createMemorySingleUseTokenStore = createMemorySingleUseTokenStore;
const crypto_1 = __importDefault(require("crypto"));
const opaque_token_1 = require("./opaque-token");
const policy_1 = require("./policy");
/** Issue a fresh single-use token for `subjectId`/`purpose`. Only the SHA-256 hash is persisted; the raw token is returned once, for the host to deliver (emailed URL, etc). */
async function issueSingleUseToken(store, options) {
    (0, policy_1.requirePositiveTtl)(options.ttlMs);
    const now = options.now ?? new Date();
    const id = crypto_1.default.randomUUID();
    const rawToken = (0, opaque_token_1.generateOpaqueToken)();
    const expiresAt = new Date(now.getTime() + options.ttlMs);
    await store.issue({
        id,
        purpose: options.purpose,
        subjectId: options.subjectId,
        tokenHash: (0, opaque_token_1.hashOpaqueToken)(rawToken),
        expiresAt,
        consumedAt: null,
    });
    return { rawToken, id, expiresAt };
}
/**
 * Redeem a single-use token: atomic, single-use, purpose-scoped.
 *
 * - Unknown token, OR a token issued for a DIFFERENT purpose -> `invalid`.
 *   These two collapse deliberately: a password-reset token presented to the
 *   invite endpoint must be indistinguishable from garbage, or the endpoint
 *   becomes an oracle for "does a token with this hash exist, for some other
 *   purpose". The store's `consume()` still reports the two separately
 *   (`not-found` vs `purpose-mismatch`) so an adapter's own tests/audit log
 *   can tell them apart.
 * - Already retired — by an earlier redeem OR by `invalidateAllFor` (the two
 *   are indistinguishable by design) -> `already-consumed`.
 * - `expiresAt <= now` (the `now` this call was given) -> `expired`, checked
 *   inside the same atomic decision as everything else — see
 *   {@link SingleUseTokenStore.consume}. Expiry writes nothing: an expired
 *   token is not retired, so it stays `expired` only for as long as `now`
 *   keeps moving forward from one call to the next. `now` is a host-supplied
 *   test seam here, exactly like `rotateRefreshToken`'s `now` in `index.ts`
 *   — not attacker input. A host that calls this again with an earlier `now`
 *   is rewinding its own clock, not defeating the contract.
 * - Otherwise -> `redeemed`, with the store's returned record.
 */
async function redeemSingleUseToken(store, rawToken, options) {
    const now = options.now ?? new Date();
    const result = await store.consume((0, opaque_token_1.hashOpaqueToken)(rawToken), { purpose: options.purpose, now });
    switch (result.status) {
        case 'not-found':
        case 'purpose-mismatch':
            return { outcome: 'invalid' };
        case 'already-consumed':
            return { outcome: 'already-consumed' };
        case 'expired':
            return { outcome: 'expired' };
        case 'consumed':
            return { outcome: 'redeemed', record: result.record };
    }
}
/**
 * In-memory reference implementation of {@link SingleUseTokenStore} — a TEST
 * DOUBLE, not for production. Ships so consumers (and this package's own
 * tests) can exercise issue/redeem without a real database. Mirrors
 * `createMemoryRefreshTokenStore`.
 */
function createMemorySingleUseTokenStore() {
    const tokens = new Map();
    function byHash(tokenHash) {
        for (const record of tokens.values()) {
            if (record.tokenHash === tokenHash)
                return record;
        }
        return undefined;
    }
    // Clones every Date field, both when a record enters the store (`issue`)
    // and when one leaves it (`consume`'s returned record). Without this, the
    // stored record aliases whatever Date object the caller happened to pass
    // in (or gets handed a reference to the store's own Date), so mutating
    // that object in place — in either direction — would retroactively change
    // the stored token's lifetime, violating the "purpose/subjectId/expiresAt
    // are IMMUTABLE after issue" invariant the port contract states.
    function cloneRecord(record) {
        return {
            ...record,
            expiresAt: new Date(record.expiresAt.getTime()),
            consumedAt: record.consumedAt === null ? null : new Date(record.consumedAt.getTime()),
        };
    }
    return {
        async issue(record) {
            if (byHash(record.tokenHash)) {
                throw new Error(`SingleUseTokenStore: duplicate tokenHash ${record.tokenHash}`);
            }
            if (tokens.has(record.id)) {
                throw new Error(`SingleUseTokenStore: duplicate id ${record.id}`);
            }
            if (record.consumedAt !== null) {
                throw new Error('SingleUseTokenStore: cannot issue an already-consumed record');
            }
            tokens.set(record.id, cloneRecord(record));
        },
        // `async` but contains NO `await` — under Node's run-to-completion
        // semantics that makes it atomic "for free": nothing can interleave
        // between the check and the write below. THAT IS NOT PROOF the
        // algorithm/port contract is sound — it proves only that JavaScript is
        // single-threaded. A real database can (and on Postgres at READ
        // COMMITTED, will) interleave two concurrent callers here. Adapter
        // authors: run `runSingleUseTokenStoreConformanceTests` (see
        // `@andrewpopov/auth-kit/conformance`) against your REAL store, not just
        // this one, before trusting your `consume()` implementation.
        async consume(tokenHash, { purpose, now }) {
            const record = byHash(tokenHash);
            if (!record)
                return { status: 'not-found' };
            if (record.purpose !== purpose)
                return { status: 'purpose-mismatch', record: cloneRecord(record) };
            if (record.consumedAt !== null)
                return { status: 'already-consumed', record: cloneRecord(record) };
            if (record.expiresAt.getTime() <= now.getTime())
                return { status: 'expired', record: cloneRecord(record) };
            record.consumedAt = new Date(now.getTime()); // clone `now` too — it's the caller's Date object
            return { status: 'consumed', record: cloneRecord(record) };
        },
        async invalidateAllFor(subjectId, purpose) {
            const now = new Date();
            for (const record of tokens.values()) {
                if (record.subjectId === subjectId && record.purpose === purpose && record.consumedAt === null) {
                    record.consumedAt = now;
                }
            }
        },
    };
}
