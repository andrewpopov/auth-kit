"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_ROTATION_GRACE_MS = exports.hashResetToken = exports.generateResetToken = exports.DEFAULT_BCRYPT_ROUNDS = void 0;
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
/**
 * @andrewpopov/auth-kit — the authentication *primitives* that drifted across the
 * custom-JWT backends (bewks, cairn, savoro, towerpower, levelup, sano-os),
 * outside express-security-kit's scope. Pure and stateless: password hashing and
 * single-use opaque tokens. The RBAC models, refresh-token stores, and 2FA flows
 * genuinely differ per app and are deliberately NOT here.
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
    const prep = (password) => (options.preHash ? prehashPassword(password) : password);
    let cachedDummy = null;
    return {
        rounds,
        hash: (password) => options.bcrypt.hash(prep(password), rounds),
        verify: (password, hash) => options.bcrypt.compare(prep(password), hash),
        dummyHash() {
            if (cachedDummy === null) {
                cachedDummy = options.bcrypt.hashSync(prep('absent-user-timing-padding'), rounds);
            }
            return cachedDummy;
        },
    };
}
/** Two presentations of the same token within this many ms of its rotation are treated as a benign multi-tab race, not theft. sano-os's value. */
exports.DEFAULT_ROTATION_GRACE_MS = 30000;
/** Issue a fresh refresh token, starting a new family (login/register/reauthentication). */
async function createRefreshToken(store, userId, ttlMs, options) {
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
 * - Already-revoked token presented again:
 *   - within `graceMs` of its rotation AND its replacement is still active ->
 *     a benign concurrent refresh (two tabs) — mints a fresh SIBLING token in
 *     the SAME family and does NOT revoke anything. This is sano-os's grace
 *     window; it is the property that will bite real users if it regresses.
 *   - otherwise -> genuine reuse (a stolen/replayed token, or a token
 *     revoked by logout) — the WHOLE family is revoked and `reuse` is
 *     returned.
 * - Otherwise -> the CAS wins: the old token is marked revoked+replaced, a
 *   new token is issued in the same family -> `rotated`.
 */
async function rotateRefreshToken(store, rawToken, ttlMs, options) {
    const now = options?.now ?? new Date();
    const graceMs = options?.graceMs ?? exports.DEFAULT_ROTATION_GRACE_MS;
    const oldTokenHash = hashOpaqueToken(rawToken);
    const rawNext = generateOpaqueToken();
    const result = await store.rotate(oldTokenHash, {
        id: crypto_1.default.randomUUID(),
        tokenHash: hashOpaqueToken(rawNext),
        expiresAt: new Date(now.getTime() + ttlMs),
    });
    switch (result.status) {
        case 'not-found':
        case 'expired':
            return { outcome: 'invalid' };
        case 'rotated':
            return {
                outcome: 'rotated',
                userId: result.session.userId,
                familyId: result.session.familyId,
                rawToken: rawNext,
                expiresAt: result.session.expiresAt,
            };
        case 'already-revoked': {
            const revokedAgeMs = result.old.revokedAt ? now.getTime() - result.old.revokedAt.getTime() : Infinity;
            const withinGrace = graceMs > 0 && revokedAgeMs >= 0 && revokedAgeMs <= graceMs;
            const replacementActive = result.replacement !== null &&
                result.replacement.revokedAt === null &&
                result.replacement.expiresAt.getTime() > now.getTime();
            if (withinGrace && replacementActive) {
                // Benign race: `rawNext`/the row passed to `store.rotate` above was
                // never persisted (the CAS rejected it), so mint a genuinely new
                // sibling token rather than trying to resurrect the discarded one.
                const sibling = await createRefreshToken(store, result.old.userId, ttlMs, {
                    familyId: result.old.familyId,
                    now,
                });
                return { outcome: 'rotated', userId: result.old.userId, familyId: sibling.familyId, rawToken: sibling.rawToken, expiresAt: sibling.expiresAt };
            }
            await store.revokeFamily(result.old.familyId);
            return { outcome: 'reuse', userId: result.old.userId, familyId: result.old.familyId };
        }
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
        async rotate(oldTokenHash, next) {
            const old = byHash(oldTokenHash);
            if (!old)
                return { status: 'not-found' };
            if (old.revokedAt !== null) {
                const replacement = old.replacedById ? sessions.get(old.replacedById) : undefined;
                return {
                    status: 'already-revoked',
                    old: { ...old },
                    replacement: replacement ? { ...replacement } : null,
                };
            }
            if (old.expiresAt.getTime() <= Date.now()) {
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
            old.revokedAt = new Date();
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
