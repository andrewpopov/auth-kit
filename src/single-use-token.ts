import crypto from 'crypto';
import { generateOpaqueToken, hashOpaqueToken } from './opaque-token';
import { requirePositiveTtl } from './policy';

// ---------------------------------------------------------------------------
// Single-use token LIFECYCLE: issue -> store -> atomic consume. The raw
// primitives (generateOpaqueToken / hashOpaqueToken / verifyOpaqueToken, in
// opaque-token.ts) are pure and stateless; "single-use" is a property only a
// storage-backed decide-and-act operation can actually provide, so it lives
// here, behind an injected `SingleUseTokenStore` port. This mirrors
// `RefreshTokenStore.rotate()` in index.ts deliberately — this package
// already solved "one atomic decide-and-act op backed by a storage port"
// once, and a second bespoke idiom for the same shape of problem would just
// be a second thing to learn.
// ---------------------------------------------------------------------------

/** One single-use token row. Storage-agnostic; a store implementation maps this to its own schema. */
export interface SingleUseTokenRecord {
  id: string;
  /** What the token authorizes: 'password-reset' | 'invite' | 'email-change' | … host-defined. */
  purpose: string;
  /** Who/what it is for — user id, invite id, whatever the host keys on. */
  subjectId: string;
  /** SHA-256 hash of the raw token (see {@link hashOpaqueToken}) — never the raw token. */
  tokenHash: string;
  expiresAt: Date;
  /**
   * Set when the token was RETIRED — by redemption or by `invalidateAllFor`.
   * `null` means still redeemable. The two retirement causes are deliberately
   * indistinguishable to the caller — see {@link SingleUseTokenStore.consume}.
   */
  consumedAt: Date | null;
}

export type ConsumeTokenStoreResult =
  | { status: 'consumed'; record: SingleUseTokenRecord }
  | { status: 'already-consumed'; record: SingleUseTokenRecord }
  | { status: 'expired'; record: SingleUseTokenRecord }
  | { status: 'purpose-mismatch'; record: SingleUseTokenRecord }
  | { status: 'not-found' };

/**
 * The storage port. Implement this against Prisma/pg/Drizzle/whatever;
 * auth-kit owns the redeem algorithm above it. `consume` is the one method
 * that MUST be atomic (a DB transaction / row lock) — see its doc below.
 */
export interface SingleUseTokenStore {
  /** Insert a brand-new token row. Rejects a `tokenHash` uniqueness violation and a non-null `consumedAt` (issuing a pre-retired token is a caller error). */
  issue(record: SingleUseTokenRecord): Promise<void>;
  /**
   * Atomic decide-AND-act, in ONE transaction / row-lock.
   *
   * **Storage invariants the adapter MUST provide** — without these, the
   * decision procedure below is not sufficient, and a "conforming" adapter
   * can still double-redeem:
   *  - `tokenHash` is GLOBALLY UNIQUE — a DB unique constraint, not an
   *    application-level check. Two rows sharing a hash let two concurrent
   *    consumes each win a DIFFERENT row while both honour the per-row
   *    contract below.
   *  - `purpose`, `subjectId`, and `expiresAt` are IMMUTABLE after issue.
   *  - The transaction's commit is the LINEARIZATION POINT: once
   *    `invalidateAllFor()` has resolved, no token it covered may
   *    subsequently return `consumed`.
   *
   * **Decision procedure**, in this precedence order, all inside ONE
   * transaction / row lock, with no gap between the decision and its write:
   *  1. No row for `tokenHash` -> `not-found`.
   *  2. Row's `purpose` !== `options.purpose` -> `purpose-mismatch`,
   *     nothing written.
   *  3. `consumedAt !== null` -> `already-consumed`, nothing written.
   *  4. `expiresAt <= now` -> `expired`, nothing written. (`<=`, matching
   *     `RefreshTokenStore.rotate`'s expiry boundary in index.ts — an
   *     exactly-at-expiry token is dead.)
   *  5. Otherwise set `consumedAt = now` and return `consumed`, with the
   *     returned record's `consumedAt` equal to `options.now`. Two
   *     concurrent callers on the same hash MUST NOT both observe
   *     `consumed` — this is the single-use compare-and-swap.
   *
   * Expiry is checked INSIDE this same atomic decision, not by the caller
   * beforehand — a caller-side expiry check is a TOCTOU.
   *
   * **Implementing steps 1-4 after a conditional UPDATE.** The natural
   * adapter is `UPDATE … SET consumed_at = $now WHERE token_hash = $h AND
   * purpose = $p AND consumed_at IS NULL AND expires_at > $now RETURNING *`.
   * One row back -> `consumed`. Zero rows back means the adapter must still
   * CLASSIFY the failure, which requires a re-read. That re-read is
   * permitted precisely because it is classification only — it selects a
   * LABEL, never an action, so there is nothing for a concurrent writer to
   * corrupt. What the contract requires is that the label be one the loser
   * is allowed to see: under a concurrent race a loser MUST report
   * `already-consumed` (never `not-found`, never `expired`) once some
   * caller has won, and MUST NOT report `consumed`.
   */
  consume(tokenHash: string, options: { purpose: string; now: Date }): Promise<ConsumeTokenStoreResult>;
  /**
   * Invalidate every outstanding token for a subject+purpose. Idempotent.
   * RETIREMENT, NOT DELETION: sets `consumedAt` on every still-outstanding
   * matching row. Adapters MUST NOT delete rows to invalidate them —
   * deletion changes the observable outcome of a later redeem from
   * `already-consumed` to `not-found`, which is exactly the
   * adapter-dependent behavior this contract exists to remove. An
   * invalidated token is deliberately indistinguishable from a redeemed one.
   */
  invalidateAllFor(subjectId: string, purpose: string): Promise<void>;
}

export interface IssueSingleUseTokenResult {
  rawToken: string;
  id: string;
  expiresAt: Date;
}

/** Issue a fresh single-use token for `subjectId`/`purpose`. Only the SHA-256 hash is persisted; the raw token is returned once, for the host to deliver (emailed URL, etc). */
export async function issueSingleUseToken(
  store: SingleUseTokenStore,
  options: { purpose: string; subjectId: string; ttlMs: number; now?: Date },
): Promise<IssueSingleUseTokenResult> {
  requirePositiveTtl(options.ttlMs);
  const now = options.now ?? new Date();
  const id = crypto.randomUUID();
  const rawToken = generateOpaqueToken();
  const expiresAt = new Date(now.getTime() + options.ttlMs);
  await store.issue({
    id,
    purpose: options.purpose,
    subjectId: options.subjectId,
    tokenHash: hashOpaqueToken(rawToken),
    expiresAt,
    consumedAt: null,
  });
  return { rawToken, id, expiresAt };
}

export type RedeemSingleUseTokenResult =
  | { outcome: 'redeemed'; record: SingleUseTokenRecord }
  | { outcome: 'already-consumed' }
  | { outcome: 'expired' }
  | { outcome: 'invalid' };

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
 * - Past `expiresAt` -> `expired`, and an expired token never subsequently
 *   becomes redeemable (checked inside the same atomic decision as
 *   everything else — see {@link SingleUseTokenStore.consume}).
 * - Otherwise -> `redeemed`, with the store's returned record.
 */
export async function redeemSingleUseToken(
  store: SingleUseTokenStore,
  rawToken: string,
  options: { purpose: string; now?: Date },
): Promise<RedeemSingleUseTokenResult> {
  const now = options.now ?? new Date();
  const result = await store.consume(hashOpaqueToken(rawToken), { purpose: options.purpose, now });

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
export function createMemorySingleUseTokenStore(): SingleUseTokenStore {
  const tokens = new Map<string, SingleUseTokenRecord>();

  function byHash(tokenHash: string): SingleUseTokenRecord | undefined {
    for (const record of tokens.values()) {
      if (record.tokenHash === tokenHash) return record;
    }
    return undefined;
  }

  return {
    async issue(record) {
      if (byHash(record.tokenHash)) {
        throw new Error(`SingleUseTokenStore: duplicate tokenHash ${record.tokenHash}`);
      }
      if (record.consumedAt !== null) {
        throw new Error('SingleUseTokenStore: cannot issue an already-consumed record');
      }
      tokens.set(record.id, { ...record });
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
      if (!record) return { status: 'not-found' };
      if (record.purpose !== purpose) return { status: 'purpose-mismatch', record: { ...record } };
      if (record.consumedAt !== null) return { status: 'already-consumed', record: { ...record } };
      if (record.expiresAt.getTime() <= now.getTime()) return { status: 'expired', record: { ...record } };

      record.consumedAt = now;
      return { status: 'consumed', record: { ...record } };
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
