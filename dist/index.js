"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_ROTATION_GRACE_MS = exports.hashResetToken = exports.generateResetToken = exports.DEFAULT_BCRYPT_ROUNDS = exports.AuthPolicyError = void 0;
exports.generateOpaqueToken = generateOpaqueToken;
exports.hashOpaqueToken = hashOpaqueToken;
exports.verifyOpaqueToken = verifyOpaqueToken;
exports.prehashPassword = prehashPassword;
exports.createPasswordHasher = createPasswordHasher;
exports.createRefreshToken = createRefreshToken;
exports.rotateRefreshToken = rotateRefreshToken;
exports.revokeRefreshToken = revokeRefreshToken;
exports.isEpochValid = isEpochValid;
exports.createMemoryRefreshTokenStore = createMemoryRefreshTokenStore;
const crypto_1 = __importDefault(require("crypto"));
const policy_1 = require("./policy");
var policy_2 = require("./policy");
Object.defineProperty(exports, "AuthPolicyError", { enumerable: true, get: function () { return policy_2.AuthPolicyError; } });
__exportStar(require("./identity"), exports);
__exportStar(require("./oidc"), exports);
/**
 * @andrewpopov/auth-kit — the authentication *primitives* that drifted across the
 * custom-JWT backends (bewks, cairn, savoro, towerpower, levelup, sano-os),
 * outside express-security-kit's scope. Password hashing and single-use opaque
 * tokens are pure and stateless. Refresh-token session rotation (below) is NOT
 * stateless — it is a stateful protocol run against an injected
 * `RefreshTokenStore` port; auth-kit owns the algorithm, never the storage
 * engine. The RBAC models, JWT library, and 2FA flows genuinely differ per app
 * and are deliberately NOT here.
 *
 * bcrypt is INJECTED (not bundled): the native-`bcrypt` apps keep their library,
 * levelup keeps `bcryptjs`, and the package forces no implementation on anyone.
 * `bcrypt` and `bcryptjs` produce cross-verifiable `$2a$`/`$2b$` hashes.
 */
exports.DEFAULT_BCRYPT_ROUNDS = 12;
// ---------------------------------------------------------------------------
// Single-use opaque tokens (password reset, invite set-password, email change).
// Only the SHA-256 HASH is ever persisted; the raw token lives only in the
// emailed URL. One primitive backs every such flow. (cairn + bewks had literal
// copies of this in lib/auth/resetToken.ts.)
// ---------------------------------------------------------------------------
/** Generate a random opaque token (64 lowercase hex chars, 256 bits). */
function generateOpaqueToken() {
    return crypto_1.default.randomBytes(32).toString('hex');
}
/** Hash a token for storage/comparison (SHA-256 hex). */
function hashOpaqueToken(token) {
    return crypto_1.default.createHash('sha256').update(token).digest('hex');
}
/** Constant-time check of a raw token against a stored SHA-256 hash. */
function verifyOpaqueToken(rawToken, storedHash) {
    const given = Buffer.from(hashOpaqueToken(rawToken));
    const want = Buffer.from(storedHash);
    if (given.length !== want.length)
        return false;
    return crypto_1.default.timingSafeEqual(given, want);
}
// Reset-token aliases — the historical names cairn/bewks used for the same primitive.
exports.generateResetToken = generateOpaqueToken;
exports.hashResetToken = hashOpaqueToken;
// ---------------------------------------------------------------------------
// Password hashing.
// ---------------------------------------------------------------------------
/**
 * Pre-hash a password with SHA-256 before bcrypt. bcrypt silently truncates
 * inputs beyond 72 bytes, so a long passphrase carries less entropy than its
 * length implies; a fixed 64-char hex digest is always within the limit while
 * encoding the full entropy. Must be applied on BOTH hash and verify. (sano-os
 * best-of-breed.) Adopt only with no existing hashes, or via a rehash-on-login
 * migration — flipping it on existing plain-bcrypt hashes invalidates them.
 */
function prehashPassword(password) {
    return crypto_1.default.createHash('sha256').update(password).digest('hex');
}
/** Create a password hasher bound to a bcrypt implementation and policy. */
function createPasswordHasher(options) {
    const rounds = options.rounds ?? exports.DEFAULT_BCRYPT_ROUNDS;
    (0, policy_1.requireBcryptRounds)(rounds);
    const prep = (password) => (options.preHash ? prehashPassword(password) : password);
    let cachedDummy = null;
    return {
        rounds,
        hash: (password) => options.bcrypt.hash(prep(password), rounds),
        verify: (password, hash) => options.bcrypt.compare(prep(password), hash),
        dummyHash() {
            if (cachedDummy === null) {
                // A random 256-bit plaintext, generated internally and never
                // retained or exposed, so no CALLER-supplied password can ever match
                // this hash (a fixed, documented plaintext like the literal string
                // previously used here would itself verify successfully — it's
                // public, right here in the source). See the `dummyHash` doc comment
                // on `PasswordHasher` for the one caveat this does NOT cover: a host
                // that wraps its own injected `bcrypt` can still observe this value.
                // Computed once and cached: the cost (and the timing-padding
                // behavior callers rely on) is paid
                // once per hasher, same as before.
                cachedDummy = options.bcrypt.hashSync(prep(crypto_1.default.randomBytes(32).toString('hex')), rounds);
            }
            return cachedDummy;
        },
    };
}
/**
 * Two presentations of the same token within this many ms of its rotation are
 * treated as a benign multi-tab race instead of theft (sano-os's value) — see
 * {@link rotateRefreshToken}, whose `graceMs` now DEFAULTS to this constant.
 * This is a real, honest reuse-detection bypass traded for UX: a stolen token
 * replayed inside the window is laundered into a legitimate-looking sibling
 * session with nothing revoked or flagged. Pass `graceMs: 0` explicitly to
 * restore the original strict behavior (any replay of an already-rotated
 * token is reuse, full stop) — cairn/mizen's deployments that need that
 * guarantee should do so explicitly rather than relying on the default.
 */
exports.DEFAULT_ROTATION_GRACE_MS = 30000;
/** Issue a fresh refresh token, starting a new family (login/register/reauthentication). */
async function createRefreshToken(store, userId, ttlMs, options) {
    (0, policy_1.requirePositiveTtl)(ttlMs);
    const now = options?.now ?? new Date();
    const familyId = options?.familyId ?? crypto_1.default.randomUUID();
    const rawToken = generateOpaqueToken();
    const expiresAt = new Date(now.getTime() + ttlMs);
    await store.createSession({
        id: crypto_1.default.randomUUID(),
        familyId,
        userId,
        tokenHash: hashOpaqueToken(rawToken),
        expiresAt,
        revokedAt: null,
        replacedById: null,
    });
    return { rawToken, familyId, expiresAt };
}
/**
 * Rotate a refresh token: single-use, atomic, with reuse detection.
 *
 * - Unknown or expired token -> `invalid` (can't be attributed to a family;
 *   nothing to revoke — mirrors cairn's reasoning).
 * - Already-revoked token presented again — the store's `rotate()` makes this
 *   call ATOMICALLY (see {@link RefreshTokenStore.rotate}; this used to be a
 *   decide-in-JS-then-act-as-a-second-call sequence and that was a TOCTOU —
 *   fixed in 0.2.1, see CHANGELOG):
 *   - within `graceMs` of its rotation AND its replacement is still active ->
 *     a benign concurrent refresh (two tabs) — a fresh SIBLING token in the
 *     SAME family was minted and nothing else was revoked. This is sano-os's
 *     grace window, OPT-IN only (see `graceMs` below).
 *   - otherwise -> genuine reuse (a stolen/replayed token, or a token
 *     revoked by logout) — the WHOLE family was revoked and `reuse` is
 *     returned.
 * - Otherwise -> the CAS wins: the old token is marked revoked+replaced, a
 *   new token is issued in the same family -> `rotated`.
 *
 * `graceMs` defaults to {@link DEFAULT_ROTATION_GRACE_MS} (30s — sano-os's
 * benign-race window, on by default as of 0.5.0; see PKG-25). This is a real,
 * honest security/UX trade: a stolen token replayed inside that window is
 * issued a fresh, valid sibling and nothing is flagged — the theft is
 * laundered into a legitimate-looking session. Pass `graceMs: 0` explicitly
 * to restore the original strict behavior (cairn/mizen's: any replay of an
 * already-rotated token is reuse, full stop). Browser clients using bearer
 * auth across multiple tabs should pair this default with a client-side
 * single-flight refresh guard (e.g. fetch-client-kit's `crossTabRefresh`) —
 * the grace window absorbs the residual race, the client control prevents
 * most races from happening at all.
 */
async function rotateRefreshToken(store, rawToken, ttlMs, options) {
    (0, policy_1.requirePositiveTtl)(ttlMs);
    const now = options?.now ?? new Date();
    const graceMs = options?.graceMs ?? exports.DEFAULT_ROTATION_GRACE_MS;
    (0, policy_1.requireGraceMs)(graceMs);
    const oldTokenHash = hashOpaqueToken(rawToken);
    const rawNext = generateOpaqueToken();
    const result = await store.rotate(oldTokenHash, { id: crypto_1.default.randomUUID(), tokenHash: hashOpaqueToken(rawNext), expiresAt: new Date(now.getTime() + ttlMs) }, { graceMs, now });
    switch (result.status) {
        case 'not-found':
        case 'expired':
            return { outcome: 'invalid' };
        case 'rotated':
        case 'benign-race':
            return {
                outcome: 'rotated',
                userId: result.session.userId,
                familyId: result.session.familyId,
                rawToken: rawNext,
                expiresAt: result.session.expiresAt,
            };
        case 'reuse':
            return { outcome: 'reuse', userId: result.userId, familyId: result.familyId };
    }
}
/** Revoke a session (logout). Finds the token's family and kills the whole family; a no-op if the token is already gone (already rotated/expired/garbage). */
async function revokeRefreshToken(store, rawToken) {
    const row = await store.findByHash(hashOpaqueToken(rawToken));
    if (row)
        await store.revokeFamily(row.familyId);
}
/**
 * Check an access token's `epoch` claim (set at mint time to `store.getEpoch`)
 * against the user's CURRENT epoch. A bump (password reset, deactivate, "log
 * out everywhere") invalidates every token minted before it — mizen's
 * `tokensValidFrom` pattern. Fails closed: an unknown user (`currentEpoch ===
 * null`) is never valid.
 */
function isEpochValid(tokenEpochMs, currentEpoch) {
    if (currentEpoch === null)
        return false;
    return tokenEpochMs >= currentEpoch.getTime();
}
/**
 * In-memory reference implementation of {@link RefreshTokenStore} — a TEST
 * DOUBLE, not for production. Ships so consumers (and this package's own
 * tests) can exercise rotation/reuse-detection without a real database.
 * Mirrors mizen's `MemoryAuthStore` test pattern.
 *
 * Has no concept of "unknown user" (it doesn't model a users table), so
 * `getEpoch` defaults an untracked user to the Unix epoch (never invalidates
 * anything) rather than `null` — call `bumpEpoch` to exercise invalidation.
 */
function createMemoryRefreshTokenStore() {
    const sessions = new Map();
    const epochs = new Map();
    function byHash(tokenHash) {
        for (const session of sessions.values()) {
            if (session.tokenHash === tokenHash)
                return session;
        }
        return undefined;
    }
    return {
        async createSession(session) {
            sessions.set(session.id, { ...session });
        },
        async findByHash(tokenHash) {
            const row = byHash(tokenHash);
            return row ? { ...row } : null;
        },
        // `async` but contains NO `await` — under Node's run-to-completion
        // semantics that makes it atomic "for free": nothing can interleave
        // between the check and the write below. THAT IS NOT PROOF the
        // algorithm/port contract is sound — it proves only that JavaScript is
        // single-threaded. A real database can (and on Postgres at READ
        // COMMITTED, will) interleave two concurrent callers here. Adapter
        // authors: run `runRefreshTokenStoreConformanceTests` (see
        // `@andrewpopov/auth-kit/conformance`) against your REAL store, not just
        // this one, before trusting your `rotate()` implementation.
        async rotate(oldTokenHash, next, { graceMs, now }) {
            const old = byHash(oldTokenHash);
            if (!old)
                return { status: 'not-found' };
            if (old.revokedAt !== null) {
                const replacement = old.replacedById ? sessions.get(old.replacedById) : undefined;
                const revokedAgeMs = now.getTime() - old.revokedAt.getTime();
                const withinGrace = graceMs > 0 && revokedAgeMs >= 0 && revokedAgeMs <= graceMs;
                const replacementActive = replacement !== undefined && replacement.revokedAt === null && replacement.expiresAt.getTime() > now.getTime();
                if (withinGrace && replacementActive) {
                    // Benign race: insert a fresh SIBLING in the same family. This
                    // check and this insert are the same synchronous stretch as the
                    // `replacementActive` read above — nothing can revoke the family
                    // in between (that gap, spanning a real await back out to JS, is
                    // exactly the 0.2.0 TOCTOU; see CHANGELOG "0.2.1 — BREAKING").
                    const sibling = {
                        id: next.id,
                        familyId: old.familyId,
                        userId: old.userId,
                        tokenHash: next.tokenHash,
                        expiresAt: next.expiresAt,
                        revokedAt: null,
                        replacedById: null,
                    };
                    sessions.set(sibling.id, sibling);
                    return { status: 'benign-race', session: { ...sibling } };
                }
                for (const session of sessions.values()) {
                    if (session.familyId === old.familyId && session.revokedAt === null)
                        session.revokedAt = now;
                }
                return { status: 'reuse', userId: old.userId, familyId: old.familyId };
            }
            if (old.expiresAt.getTime() <= now.getTime()) {
                return { status: 'expired', old: { ...old } };
            }
            const session = {
                id: next.id,
                familyId: old.familyId,
                userId: old.userId,
                tokenHash: next.tokenHash,
                expiresAt: next.expiresAt,
                revokedAt: null,
                replacedById: null,
            };
            sessions.set(session.id, session);
            old.revokedAt = now;
            old.replacedById = session.id;
            return { status: 'rotated', session: { ...session } };
        },
        async revokeFamily(familyId) {
            const now = new Date();
            for (const session of sessions.values()) {
                if (session.familyId === familyId && session.revokedAt === null)
                    session.revokedAt = now;
            }
        },
        async revokeAllForUser(userId) {
            const now = new Date();
            for (const session of sessions.values()) {
                if (session.userId === userId && session.revokedAt === null)
                    session.revokedAt = now;
            }
        },
        async getEpoch(userId) {
            return epochs.get(userId) ?? new Date(0);
        },
        async bumpEpoch(userId) {
            const storedMs = epochs.get(userId)?.getTime() ?? 0;
            const next = new Date(Math.max(Date.now(), storedMs) + 1);
            epochs.set(userId, next);
            return next;
        },
    };
}
