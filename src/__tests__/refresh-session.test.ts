import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  createMemoryRefreshTokenStore,
  createRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  isEpochValid,
  hashOpaqueToken,
  DEFAULT_ROTATION_GRACE_MS,
  type RefreshTokenStore,
} from '../index';

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

describe('createRefreshToken', () => {
  it('issues a token, starting a new family, storing only its hash', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    expect(issued.rawToken).toMatch(/^[0-9a-f]{64}$/);
    expect(issued.familyId).toBeTruthy();

    const row = await store.findByHash(hashOpaqueToken(issued.rawToken));
    expect(row).not.toBeNull();
    expect(row!.tokenHash).toBe(hashOpaqueToken(issued.rawToken));
    // property 6: the stored value is a hash, never the raw token.
    expect(row!.tokenHash).not.toBe(issued.rawToken);
    expect(JSON.stringify(row)).not.toContain(issued.rawToken);
  });
});

describe('rotateRefreshToken — normal rotation', () => {
  it('rotates to a new token in the same family and the old token can no longer rotate', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    const result = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(result.outcome).toBe('rotated');
    if (result.outcome !== 'rotated') throw new Error('unreachable');
    expect(result.familyId).toBe(issued.familyId);
    expect(result.userId).toBe('user-1');
    expect(result.rawToken).not.toBe(issued.rawToken);
  });

  it('rejects an unknown token as invalid', async () => {
    const store = createMemoryRefreshTokenStore();
    const result = await rotateRefreshToken(store, 'not-a-real-token', TTL_MS);
    expect(result.outcome).toBe('invalid');
  });
});

describe('property 4 — a revoked/expired token is rejected', () => {
  it('rejects an already-expired, never-rotated token as invalid (not reuse — nothing to attribute)', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', -1); // expiresAt already in the past

    const result = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(result.outcome).toBe('invalid');
  });

  it('rejects a logged-out (revoked, never rotated) token, and does not resurrect it via the grace window', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);
    await revokeRefreshToken(store, issued.rawToken);

    const result = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    // Revoked with no replacement -> not a benign race under any grace window.
    expect(result.outcome).toBe('reuse');
  });
});

describe('property 5 — epoch invalidates outstanding tokens globally', () => {
  it('a token minted before a bump is invalid after it; a fresh bump post-issue is valid', async () => {
    const store = createMemoryRefreshTokenStore();
    const epochBefore = await store.getEpoch('user-1');
    const mintedAtMs = Date.now();
    expect(isEpochValid(mintedAtMs, epochBefore)).toBe(true);

    const bumped = await store.bumpEpoch('user-1'); // e.g. password reset / deactivate
    expect(isEpochValid(mintedAtMs, bumped)).toBe(false);

    const currentEpoch = await store.getEpoch('user-1');
    expect(isEpochValid(Date.now() + 1000, currentEpoch)).toBe(true);
  });

  it('fails closed for an unknown epoch', () => {
    expect(isEpochValid(Date.now(), null)).toBe(false);
  });

  it('bumpEpoch is strictly monotonic even for back-to-back bumps', async () => {
    const store = createMemoryRefreshTokenStore();
    const first = await store.bumpEpoch('user-1');
    const second = await store.bumpEpoch('user-1');
    expect(second.getTime()).toBeGreaterThan(first.getTime());
  });
});

describe('property 1 — rotation is atomic / single-use', () => {
  it('two concurrent rotations of the same token: exactly one wins the CAS (grace window disabled to make the loser deterministic)', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    const [a, b] = await Promise.all([
      rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: 0 }),
      rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: 0 }),
    ]);

    const outcomes = [a.outcome, b.outcome].sort();
    expect(outcomes).toEqual(['reuse', 'rotated']);
  });

  it('the CAS primitive itself: N concurrent store.rotate() calls on one token, exactly one returns "rotated"', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);
    const oldHash = hashOpaqueToken(issued.rawToken);

    const attempts = Array.from({ length: 5 }, () =>
      store.rotate(
        oldHash,
        { id: crypto.randomUUID(), tokenHash: hashOpaqueToken(crypto.randomUUID()), expiresAt: new Date(Date.now() + TTL_MS) },
        { graceMs: 0, now: new Date() },
      ),
    );
    const results = await Promise.all(attempts);
    const rotatedCount = results.filter((r) => r.status === 'rotated').length;
    expect(rotatedCount).toBe(1);
  });
});

describe('property 2 — replay of an already-rotated token kills the whole family', () => {
  it('replaying the old token outside the grace window revokes the entire family, including the legitimate successor', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    const rotated = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(rotated.outcome).toBe('rotated');
    if (rotated.outcome !== 'rotated') throw new Error('unreachable');

    // Replay the ORIGINAL (now-rotated) token well outside any grace window.
    const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: 0 });
    expect(replay.outcome).toBe('reuse');
    expect(replay.familyId).toBe(issued.familyId);

    // The whole family is dead — the legitimate successor token no longer works either.
    const successorAttempt = await rotateRefreshToken(store, rotated.rawToken, TTL_MS);
    expect(successorAttempt.outcome).toBe('reuse');
  });
});

describe('property 3 — the benign race is NOT treated as an attack', () => {
  it('two tabs refreshing near-simultaneously within the grace window both come away with a working session; the family survives', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    // Tab A wins the rotation.
    const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS });
    expect(winner.outcome).toBe('rotated');
    if (winner.outcome !== 'rotated') throw new Error('unreachable');

    // Tab B presents the SAME (now-rotated) old token an instant later, still
    // within the grace window. This must NOT be treated as reuse.
    const loser = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS });
    expect(loser.outcome).toBe('rotated');
    if (loser.outcome !== 'rotated') throw new Error('unreachable');
    expect(loser.familyId).toBe(issued.familyId);
    expect(loser.rawToken).not.toBe(winner.rawToken);

    // The family must still be alive: both the winner's and the benign-race
    // sibling's tokens keep working afterward.
    const winnerNextHop = await rotateRefreshToken(store, winner.rawToken, TTL_MS);
    expect(winnerNextHop.outcome).toBe('rotated');
    const loserNextHop = await rotateRefreshToken(store, loser.rawToken, TTL_MS);
    expect(loserNextHop.outcome).toBe('rotated');
  });

  it('outside the grace window, the identical replay IS treated as reuse (proves the window, not just "any replay is fine")', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(winner.outcome).toBe('rotated');

    // Same replay, but graceMs: 0 — must now be reuse, not a benign race.
    const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: 0 });
    expect(replay.outcome).toBe('reuse');
  });
});

describe('Defect B — graceMs defaults to 0 (strict, opt-in-only grace window)', () => {
  it('a replay of an already-rotated token WITHOUT an explicit graceMs is reuse, not a benign race, even though a replacement is active', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);

    const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS); // no options at all
    expect(winner.outcome).toBe('rotated');

    // Replayed an instant later — under the OLD default (30s) this would have
    // been a benign race. Under the new default (0) it must be reuse.
    const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(replay.outcome).toBe('reuse');
  });

  it('DEFAULT_ROTATION_GRACE_MS is still exported as the suggested opt-in value, but is not applied unless passed explicitly', async () => {
    expect(DEFAULT_ROTATION_GRACE_MS).toBe(30_000);

    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);
    const winner = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(winner.outcome).toBe('rotated');

    // Opting in explicitly restores the benign-race behavior.
    const replay = await rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS });
    expect(replay.outcome).toBe('rotated');
  });
});

describe('Defect A regression — the benign-race branch must never resurrect a revoked family (TOCTOU)', () => {
  it(
    'a family revoked concurrently with a benign-race replay must never leave a live token in that family, regardless of ' +
      'which of the two "wins" — CANARY: this assertion fails against the old (v0.2.0) two-call decide-in-JS-then-act-' +
      'as-a-second-call design, where the sibling insert is unconditional and blind to the concurrent revoke. See the ' +
      'PR description for the manual before/after run.',
    async () => {
      const store = createMemoryRefreshTokenStore();
      const issued = await createRefreshToken(store, 'user-1', TTL_MS);
      const rotated = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
      expect(rotated.outcome).toBe('rotated');
      if (rotated.outcome !== 'rotated') throw new Error('unreachable');
      const familyId = rotated.familyId;

      // Attacker replays the stolen original token within the grace window
      // (opted in here to exercise the benign-race path at all), racing
      // against a concurrent revoke of the whole family — a victim logout,
      // an admin action, or a password reset firing at the same moment.
      const [replay] = await Promise.all([
        rotateRefreshToken(store, issued.rawToken, TTL_MS, { graceMs: DEFAULT_ROTATION_GRACE_MS }),
        store.revokeFamily(familyId),
      ]);

      // Whichever happened "first", the invariant must hold afterward: no
      // live (non-revoked) token exists in a family that was revoked.
      if (replay.outcome === 'rotated') {
        const row = await store.findByHash(hashOpaqueToken(replay.rawToken));
        expect(row).not.toBeNull();
        expect(row!.revokedAt).not.toBeNull();
      } else {
        expect(replay.outcome).toBe('reuse');
      }

      // The original successor token must also be dead — the family is fully gone.
      const successorStillAlive = await store.findByHash(hashOpaqueToken(rotated.rawToken));
      expect(successorStillAlive?.revokedAt).not.toBeNull();
    },
  );
});

describe('revokeRefreshToken (logout)', () => {
  it('kills the whole family and is a silent no-op for an already-gone token', async () => {
    const store = createMemoryRefreshTokenStore();
    const issued = await createRefreshToken(store, 'user-1', TTL_MS);
    await revokeRefreshToken(store, issued.rawToken);

    const attempt = await rotateRefreshToken(store, issued.rawToken, TTL_MS);
    expect(attempt.outcome).toBe('reuse');

    await expect(revokeRefreshToken(store, 'garbage-token')).resolves.toBeUndefined();
  });
});

describe('revokeAllForUser (logout-everywhere)', () => {
  it('kills every family for the user, leaving other users unaffected', async () => {
    const store = createMemoryRefreshTokenStore();
    const sessionA = await createRefreshToken(store, 'user-1', TTL_MS);
    const sessionB = await createRefreshToken(store, 'user-1', TTL_MS); // second device/family
    const otherUser = await createRefreshToken(store, 'user-2', TTL_MS);

    await store.revokeAllForUser('user-1');

    expect((await rotateRefreshToken(store, sessionA.rawToken, TTL_MS)).outcome).toBe('reuse');
    expect((await rotateRefreshToken(store, sessionB.rawToken, TTL_MS)).outcome).toBe('reuse');
    expect((await rotateRefreshToken(store, otherUser.rawToken, TTL_MS)).outcome).toBe('rotated');
  });
});

describe('type-level: RefreshTokenStore is a satisfiable port', () => {
  it('createMemoryRefreshTokenStore satisfies the RefreshTokenStore interface', () => {
    const store: RefreshTokenStore = createMemoryRefreshTokenStore();
    expect(store).toBeDefined();
  });
});
