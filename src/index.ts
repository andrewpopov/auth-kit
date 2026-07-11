import crypto from 'crypto';

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

export const DEFAULT_BCRYPT_ROUNDS = 12;

// ---------------------------------------------------------------------------
// Single-use opaque tokens (password reset, invite set-password, email change).
// Only the SHA-256 HASH is ever persisted; the raw token lives only in the
// emailed URL. One primitive backs every such flow. (cairn + bewks had literal
// copies of this in lib/auth/resetToken.ts.)
// ---------------------------------------------------------------------------

/** Generate a random opaque token (64 lowercase hex chars, 256 bits). */
export function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/** Hash a token for storage/comparison (SHA-256 hex). */
export function hashOpaqueToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Constant-time check of a raw token against a stored SHA-256 hash. */
export function verifyOpaqueToken(rawToken: string, storedHash: string): boolean {
  const given = Buffer.from(hashOpaqueToken(rawToken));
  const want = Buffer.from(storedHash);
  if (given.length !== want.length) return false;
  return crypto.timingSafeEqual(given, want);
}

// Reset-token aliases — the historical names cairn/bewks used for the same primitive.
export const generateResetToken = generateOpaqueToken;
export const hashResetToken = hashOpaqueToken;

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
export function prehashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

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
export function createPasswordHasher(options: PasswordHasherOptions): PasswordHasher {
  const rounds = options.rounds ?? DEFAULT_BCRYPT_ROUNDS;
  const prep = (password: string): string => (options.preHash ? prehashPassword(password) : password);
  let cachedDummy: string | null = null;

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

// ---------------------------------------------------------------------------
// Refresh-token session rotation with reuse detection.
//
// Hand-written five times across the fleet (cairn, mizen, sano-os, smarthome,
// savoro), each getting the subtleties differently. This composes: cairn's
// family-kill-on-replay (the strict DEFAULT), mizen's `tokensValidFrom` epoch
// for global invalidation, and sano-os's benign-race grace window (two tabs
// refreshing near-simultaneously don't have to nuke the session) as an
// OPT-IN — a grace window is a real reuse-detection bypass traded for UX, not
// a pure win, so it does not ship on by default.
//
// A refresh token IS an opaque token: generate -> sha256 -> store the hash ->
// compare (the primitives above). This layer adds the rotation state machine
// on top. Storage is INJECTED via `RefreshTokenStore` — mizen's `AuthStore`
// port is the proven shape; auth-kit owns only the algorithm, never the
// storage engine (Prisma/pg/Drizzle all differ per app).
// `createMemoryRefreshTokenStore()` ships as a reference implementation / test
// double (mizen's `MemoryAuthStore` pattern).
//
// Deliberately NOT here: RBAC, the JWT library (embed/verify the `epoch`
// claim yourself via `isEpochValid`), cookie handling, the user model/CRUD.
// Those genuinely differ per app.
// ---------------------------------------------------------------------------

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

export type RotateStoreResult =
  | { status: 'rotated'; session: RefreshSessionRecord }
  /**
   * Benign multi-tab race: `oldTokenHash` was already revoked, but within
   * `graceMs` AND its replacement was (at the moment of THIS atomic call,
   * re-checked fresh — never from a stale read) still active. The store
   * inserted `next` as a new sibling session in the same family and returns
   * it here.
   */
  | { status: 'benign-race'; session: RefreshSessionRecord }
  /**
   * Genuine reuse (stolen/replayed token, or a token revoked by logout/
   * password-reset/admin action): the store revoked every still-active
   * session in the family, atomically with the check, before returning.
   */
  | { status: 'reuse'; userId: string; familyId: string }
  | { status: 'expired'; old: RefreshSessionRecord }
  | { status: 'not-found' };

/**
 * The storage port. Implement this against Prisma/pg/Drizzle/whatever; auth-kit
 * owns the rotation algorithm above it. `rotate` is the one method that MUST be
 * atomic (a DB transaction / row lock) — see its doc below.
 */
export interface RefreshTokenStore {
  /** Insert a brand-new session row (fresh login). */
  createSession(session: RefreshSessionRecord): Promise<void>;
  /** Look up a row by token hash (used by e.g. logout to find its family). */
  findByHash(tokenHash: string): Promise<RefreshSessionRecord | null>;
  /**
   * Atomic decide-AND-act, in ONE transaction / row-lock — this is the entire
   * rotation state machine, including the benign-race-vs-reuse judgment call
   * and its consequence (insert or family-revoke). Nothing about the decision
   * may be read outside this call and acted on later: a second, separate
   * store call driven by a snapshot from a PRIOR `rotate()` result is exactly
   * the TOCTOU auth-kit v0.2.0 shipped (see CHANGELOG "0.2.1 — BREAKING").
   *
   * Steps, all inside the one transaction:
   *  1. No row for `oldTokenHash` -> `not-found`.
   *  2. Row not revoked, not expired -> mark it revoked (`revokedAt = now`,
   *     `replacedById = next.id`), insert `next` (`userId`/`familyId` copied
   *     from the row) -> `rotated`. Two concurrent callers racing the same
   *     `oldTokenHash` MUST NOT both observe `rotated` — this is the
   *     single-use compare-and-swap; it is what a lock/`SELECT ... FOR
   *     UPDATE`/conditional `UPDATE ... WHERE revoked_at IS NULL` buys you.
   *  3. Row not revoked, but past `expiresAt` -> `expired`.
   *  4. Row already revoked: resolve its replacement via `replacedById`
   *     (fresh, in THIS transaction — not a value carried in from outside),
   *     and compute, using `options.now`:
   *       - `revokedAgeMs = now - row.revokedAt`
   *       - `withinGrace = options.graceMs > 0 && revokedAgeMs in [0, graceMs]`
   *       - `replacementActive = replacement exists, not revoked, not expired`
   *     - `withinGrace && replacementActive` -> insert `next` as a NEW
   *       sibling row in the same family (`revokedAt: null`,
   *       `replacedById: null`) -> `benign-race`, returning the inserted row.
   *     - otherwise -> revoke every still-active row sharing the family
   *       (same effect as {@link RefreshTokenStore.revokeFamily}) -> `reuse`.
   *  The check in step 4 and its action (insert or revoke) MUST happen
   *  without releasing the lock/leaving the transaction in between — that is
   *  the fix for the TOCTOU: a concurrent family-kill landing after this
   *  call's read but before its write is impossible by construction, because
   *  there IS no gap between them for a caller to observe or interleave into.
   */
  rotate(oldTokenHash: string, next: NewSessionFields, options: { graceMs: number; now: Date }): Promise<RotateStoreResult>;
  /** Revoke every still-active row sharing a family (logout of one session). Idempotent — safe to call on an already-dead family. */
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

/**
 * Two presentations of the same token within this many ms of its rotation MAY
 * be treated as a benign multi-tab race instead of theft (sano-os's value) —
 * but only if a consumer opts in via `{ graceMs: DEFAULT_ROTATION_GRACE_MS }`.
 * NOT the default (see {@link rotateRefreshToken}): a grace window is an
 * explicit reuse-detection bypass traded for UX, and a stolen token replayed
 * inside it is laundered into a legitimate-looking sibling session with
 * nothing revoked or flagged. cairn deliberately refuses this trade. A
 * security default must be the strict one.
 */
export const DEFAULT_ROTATION_GRACE_MS = 30_000;

export interface CreateRefreshTokenResult {
  rawToken: string;
  familyId: string;
  expiresAt: Date;
}

/** Issue a fresh refresh token, starting a new family (login/register/reauthentication). */
export async function createRefreshToken(
  store: RefreshTokenStore,
  userId: string,
  ttlMs: number,
  options?: { familyId?: string; now?: Date },
): Promise<CreateRefreshTokenResult> {
  const now = options?.now ?? new Date();
  const familyId = options?.familyId ?? crypto.randomUUID();
  const rawToken = generateOpaqueToken();
  const expiresAt = new Date(now.getTime() + ttlMs);
  await store.createSession({
    id: crypto.randomUUID(),
    familyId,
    userId,
    tokenHash: hashOpaqueToken(rawToken),
    expiresAt,
    revokedAt: null,
    replacedById: null,
  });
  return { rawToken, familyId, expiresAt };
}

export type RotateRefreshTokenResult =
  | { outcome: 'rotated'; userId: string; familyId: string; rawToken: string; expiresAt: Date }
  | { outcome: 'reuse'; userId: string; familyId: string }
  | { outcome: 'invalid' };

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
 * `graceMs` defaults to `0` (strict — cairn/mizen's behavior: any replay of
 * an already-rotated token is reuse, full stop). Passing
 * `DEFAULT_ROTATION_GRACE_MS` opts into sano-os's 30s benign-race window,
 * which is a real, honest security/UX trade: a stolen token replayed inside
 * that window is issued a fresh, valid sibling and nothing is flagged — the
 * theft is laundered into a legitimate-looking session. Opt in only with eyes
 * open (see README).
 */
export async function rotateRefreshToken(
  store: RefreshTokenStore,
  rawToken: string,
  ttlMs: number,
  options?: { graceMs?: number; now?: Date },
): Promise<RotateRefreshTokenResult> {
  const now = options?.now ?? new Date();
  const graceMs = options?.graceMs ?? 0;
  const oldTokenHash = hashOpaqueToken(rawToken);
  const rawNext = generateOpaqueToken();

  const result = await store.rotate(
    oldTokenHash,
    { id: crypto.randomUUID(), tokenHash: hashOpaqueToken(rawNext), expiresAt: new Date(now.getTime() + ttlMs) },
    { graceMs, now },
  );

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
export async function revokeRefreshToken(store: RefreshTokenStore, rawToken: string): Promise<void> {
  const row = await store.findByHash(hashOpaqueToken(rawToken));
  if (row) await store.revokeFamily(row.familyId);
}

/**
 * Check an access token's `epoch` claim (set at mint time to `store.getEpoch`)
 * against the user's CURRENT epoch. A bump (password reset, deactivate, "log
 * out everywhere") invalidates every token minted before it — mizen's
 * `tokensValidFrom` pattern. Fails closed: an unknown user (`currentEpoch ===
 * null`) is never valid.
 */
export function isEpochValid(tokenEpochMs: number, currentEpoch: Date | null): boolean {
  if (currentEpoch === null) return false;
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
export function createMemoryRefreshTokenStore(): RefreshTokenStore {
  const sessions = new Map<string, RefreshSessionRecord>();
  const epochs = new Map<string, Date>();

  function byHash(tokenHash: string): RefreshSessionRecord | undefined {
    for (const session of sessions.values()) {
      if (session.tokenHash === tokenHash) return session;
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
      if (!old) return { status: 'not-found' };

      if (old.revokedAt !== null) {
        const replacement = old.replacedById ? sessions.get(old.replacedById) : undefined;
        const revokedAgeMs = now.getTime() - old.revokedAt.getTime();
        const withinGrace = graceMs > 0 && revokedAgeMs >= 0 && revokedAgeMs <= graceMs;
        const replacementActive =
          replacement !== undefined && replacement.revokedAt === null && replacement.expiresAt.getTime() > now.getTime();

        if (withinGrace && replacementActive) {
          // Benign race: insert a fresh SIBLING in the same family. This
          // check and this insert are the same synchronous stretch as the
          // `replacementActive` read above — nothing can revoke the family
          // in between (that gap, spanning a real await back out to JS, is
          // exactly the 0.2.0 TOCTOU; see CHANGELOG "0.2.1 — BREAKING").
          const sibling: RefreshSessionRecord = {
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
          if (session.familyId === old.familyId && session.revokedAt === null) session.revokedAt = now;
        }
        return { status: 'reuse', userId: old.userId, familyId: old.familyId };
      }

      if (old.expiresAt.getTime() <= now.getTime()) {
        return { status: 'expired', old: { ...old } };
      }

      const session: RefreshSessionRecord = {
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
        if (session.familyId === familyId && session.revokedAt === null) session.revokedAt = now;
      }
    },

    async revokeAllForUser(userId) {
      const now = new Date();
      for (const session of sessions.values()) {
        if (session.userId === userId && session.revokedAt === null) session.revokedAt = now;
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
