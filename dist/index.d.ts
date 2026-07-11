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
export declare const DEFAULT_BCRYPT_ROUNDS = 12;
/** Generate a random opaque token (64 lowercase hex chars, 256 bits). */
export declare function generateOpaqueToken(): string;
/** Hash a token for storage/comparison (SHA-256 hex). */
export declare function hashOpaqueToken(token: string): string;
/** Constant-time check of a raw token against a stored SHA-256 hash. */
export declare function verifyOpaqueToken(rawToken: string, storedHash: string): boolean;
export declare const generateResetToken: typeof generateOpaqueToken;
export declare const hashResetToken: typeof hashOpaqueToken;
/**
 * Pre-hash a password with SHA-256 before bcrypt. bcrypt silently truncates
 * inputs beyond 72 bytes, so a long passphrase carries less entropy than its
 * length implies; a fixed 64-char hex digest is always within the limit while
 * encoding the full entropy. Must be applied on BOTH hash and verify. (sano-os
 * best-of-breed.) Adopt only with no existing hashes, or via a rehash-on-login
 * migration — flipping it on existing plain-bcrypt hashes invalidates them.
 */
export declare function prehashPassword(password: string): string;
/** The subset of the `bcrypt` / `bcryptjs` API this package uses. */
export interface BcryptLike {
    hash(data: string, rounds: number): Promise<string>;
    compare(data: string, hash: string): Promise<boolean>;
    hashSync(data: string, rounds: number): string;
}
export interface PasswordHasherOptions {
    /** The app's bcrypt implementation (`bcrypt` or `bcryptjs`). */
    bcrypt: BcryptLike;
    /** Cost factor. Default 12. */
    rounds?: number;
    /** SHA-256 pre-hash before bcrypt (see {@link prehashPassword}). Default false. */
    preHash?: boolean;
}
export interface PasswordHasher {
    readonly rounds: number;
    /** Hash a password. */
    hash(password: string): Promise<string>;
    /** Verify a password against a stored hash. */
    verify(password: string, hash: string): Promise<boolean>;
    /**
     * A valid bcrypt hash that no real password matches, computed once. Compare an
     * incoming password against it on the account-absent / no-password branch so
     * login timing stays uniform and leaks no account-existence signal.
     */
    dummyHash(): string;
}
/** Create a password hasher bound to a bcrypt implementation and policy. */
export declare function createPasswordHasher(options: PasswordHasherOptions): PasswordHasher;
/** One refresh-token row. Storage-agnostic; a store implementation maps this to its own schema. */
export interface RefreshSessionRecord {
    id: string;
    /** Groups every token issued/rotated within one login session (a "family"). */
    familyId: string;
    userId: string;
    /** SHA-256 hash of the opaque token (see {@link hashOpaqueToken}) — never the raw token. */
    tokenHash: string;
    expiresAt: Date;
    /** Set on rotation, reuse-kill, or logout. `null` means still active. */
    revokedAt: Date | null;
    /** Set ONLY when revocation was caused by rotation — points at the successor row. */
    replacedById: string | null;
}
/** Fields the caller supplies for the row `rotate` inserts on success; `userId`/`familyId` are copied from the row being rotated. */
export type NewSessionFields = Pick<RefreshSessionRecord, 'id' | 'tokenHash' | 'expiresAt'>;
export type RotateStoreResult = {
    status: 'rotated';
    session: RefreshSessionRecord;
} | {
    status: 'already-revoked';
    old: RefreshSessionRecord;
    replacement: RefreshSessionRecord | null;
} | {
    status: 'expired';
    old: RefreshSessionRecord;
} | {
    status: 'not-found';
};
/**
 * The storage port. Implement this against Prisma/pg/Drizzle/whatever; auth-kit
 * owns the rotation algorithm above it. `rotate` is the one method that MUST be
 * atomic (a DB transaction / row lock) — it is both the single-use compare-
 * and-swap (exactly one concurrent rotation of the same token may win) and the
 * read that supplies the facts (`old`, `replacement`) the algorithm needs to
 * tell a benign multi-tab race from real reuse.
 */
export interface RefreshTokenStore {
    /** Insert a brand-new session row (fresh login, or a benign-race sibling). */
    createSession(session: RefreshSessionRecord): Promise<void>;
    /** Look up a row by token hash (used by e.g. logout to find its family). */
    findByHash(tokenHash: string): Promise<RefreshSessionRecord | null>;
    /**
     * Atomic compare-and-swap + insert, in one transaction:
     *  - no row for `oldTokenHash` -> `not-found`.
     *  - row already revoked -> `already-revoked`, returning the row AND its
     *    replacement (resolved via `replacedById`, if any) so the algorithm can
     *    judge the grace window.
     *  - row not revoked but past `expiresAt` -> `expired`.
     *  - otherwise: mark the row revoked (`revokedAt = now`, `replacedById =
     *    next.id`) and insert `next` (`userId`/`familyId` copied from the row)
     *    -> `rotated`. Two concurrent callers racing the same `oldTokenHash`
     *    MUST NOT both observe `rotated` — the transaction/row-lock is what
     *    guarantees single-use.
     */
    rotate(oldTokenHash: string, next: NewSessionFields): Promise<RotateStoreResult>;
    /** Revoke every still-active row sharing a family (reuse detected, or logout of one session). */
    revokeFamily(familyId: string): Promise<void>;
    /** Revoke every still-active row for a user, across all families (logout-everywhere). */
    revokeAllForUser(userId: string): Promise<void>;
    /** The user's current auth epoch (`tokensValidFrom`), or `null` if the user is unknown to the store. */
    getEpoch(userId: string): Promise<Date | null>;
    /**
     * Bump the epoch STRICTLY forward (password reset / deactivate), invalidating
     * every access token whose `epoch` claim predates it. Must be monotonic even
     * for two bumps in the same millisecond: `max(now, storedEpoch) + 1ms`
     * (sano-os's formula).
     */
    bumpEpoch(userId: string): Promise<Date>;
}
/** Two presentations of the same token within this many ms of its rotation are treated as a benign multi-tab race, not theft. sano-os's value. */
export declare const DEFAULT_ROTATION_GRACE_MS = 30000;
export interface CreateRefreshTokenResult {
    rawToken: string;
    familyId: string;
    expiresAt: Date;
}
/** Issue a fresh refresh token, starting a new family (login/register/reauthentication). */
export declare function createRefreshToken(store: RefreshTokenStore, userId: string, ttlMs: number, options?: {
    familyId?: string;
    now?: Date;
}): Promise<CreateRefreshTokenResult>;
export type RotateRefreshTokenResult = {
    outcome: 'rotated';
    userId: string;
    familyId: string;
    rawToken: string;
    expiresAt: Date;
} | {
    outcome: 'reuse';
    userId: string;
    familyId: string;
} | {
    outcome: 'invalid';
};
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
export declare function rotateRefreshToken(store: RefreshTokenStore, rawToken: string, ttlMs: number, options?: {
    graceMs?: number;
    now?: Date;
}): Promise<RotateRefreshTokenResult>;
/** Revoke a session (logout). Finds the token's family and kills the whole family; a no-op if the token is already gone (already rotated/expired/garbage). */
export declare function revokeRefreshToken(store: RefreshTokenStore, rawToken: string): Promise<void>;
/**
 * Check an access token's `epoch` claim (set at mint time to `store.getEpoch`)
 * against the user's CURRENT epoch. A bump (password reset, deactivate, "log
 * out everywhere") invalidates every token minted before it — mizen's
 * `tokensValidFrom` pattern. Fails closed: an unknown user (`currentEpoch ===
 * null`) is never valid.
 */
export declare function isEpochValid(tokenEpochMs: number, currentEpoch: Date | null): boolean;
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
export declare function createMemoryRefreshTokenStore(): RefreshTokenStore;
