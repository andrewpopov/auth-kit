import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  createMemorySingleUseTokenStore,
  issueSingleUseToken,
  redeemSingleUseToken,
  hashOpaqueToken,
  type SingleUseTokenStore,
} from '../index';

const TTL_MS = 15 * 60 * 1000; // 15 minutes, a typical password-reset window
const PURPOSE = 'password-reset';
const SUBJECT = 'user-1';

describe('issueSingleUseToken', () => {
  it.each([0, -1, 1.5])('rejects invalid TTLs: %s', async (ttlMs) => {
    await expect(
      issueSingleUseToken(createMemorySingleUseTokenStore(), { purpose: PURPOSE, subjectId: SUBJECT, ttlMs }),
    ).rejects.toThrow(/ttlMs/);
  });

  it('issues a token, storing only its hash, with expiresAt = now + ttlMs', async () => {
    const store = createMemorySingleUseTokenStore();
    const now = new Date('2026-01-01T00:00:00.000Z');
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS, now });

    expect(issued.rawToken).toMatch(/^[0-9a-f]{64}$/);
    expect(issued.id).toBeTruthy();
    expect(issued.expiresAt.getTime()).toBe(now.getTime() + TTL_MS);
    expect(JSON.stringify(issued)).not.toContain(hashOpaqueToken(issued.rawToken));
  });
});

describe('redeemSingleUseToken — happy path', () => {
  it('redeems, with consumedAt === now and the issued purpose/subjectId on the record', async () => {
    const store = createMemorySingleUseTokenStore();
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS });
    const now = new Date();

    const result = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE, now });
    expect(result.outcome).toBe('redeemed');
    if (result.outcome !== 'redeemed') throw new Error('unreachable');
    expect(result.record.id).toBe(issued.id);
    expect(result.record.purpose).toBe(PURPOSE);
    expect(result.record.subjectId).toBe(SUBJECT);
    expect(result.record.tokenHash).toBe(hashOpaqueToken(issued.rawToken));
    expect(result.record.consumedAt).toEqual(now);
  });
});

describe('redeemSingleUseToken — unknown token', () => {
  it('an unknown token is invalid', async () => {
    const store = createMemorySingleUseTokenStore();
    const result = await redeemSingleUseToken(store, 'not-a-real-token', { purpose: PURPOSE });
    expect(result.outcome).toBe('invalid');
  });
});

describe('redeemSingleUseToken — sequential replay', () => {
  it('a second redeem of the same token reports already-consumed, not redeemed again', async () => {
    const store = createMemorySingleUseTokenStore();
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS });

    const first = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE });
    expect(first.outcome).toBe('redeemed');

    const second = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE });
    expect(second.outcome).toBe('already-consumed');
  });
});

describe('purpose scoping', () => {
  it('redeeming under the wrong purpose is invalid at the algorithm layer, purpose-mismatch at the store layer, and the token remains redeemable under its real purpose', async () => {
    const store = createMemorySingleUseTokenStore();
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS });

    const wrongPurposeAlgo = await redeemSingleUseToken(store, issued.rawToken, { purpose: 'invite' });
    expect(wrongPurposeAlgo.outcome).toBe('invalid');

    const storeResult = await store.consume(hashOpaqueToken(issued.rawToken), { purpose: 'invite', now: new Date() });
    expect(storeResult.status).toBe('purpose-mismatch');

    // Nothing was written — the token is still redeemable under its real purpose.
    const realPurpose = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE });
    expect(realPurpose.outcome).toBe('redeemed');
  });
});

describe('expiry', () => {
  it('a token redeemed after expiresAt reports expired', async () => {
    const store = createMemorySingleUseTokenStore();
    const issuedAt = new Date('2026-01-01T00:00:00.000Z');
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS, now: issuedAt });

    const afterExpiry = new Date(issued.expiresAt.getTime() + 1);
    const result = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE, now: afterExpiry });
    expect(result.outcome).toBe('expired');
  });

  it('the expiry boundary is inclusive: redeeming exactly at expiresAt is expired', async () => {
    const store = createMemorySingleUseTokenStore();
    const issuedAt = new Date('2026-01-01T00:00:00.000Z');
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS, now: issuedAt });

    const atExpiry = new Date(issued.expiresAt.getTime());
    const result = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE, now: atExpiry });
    expect(result.outcome).toBe('expired');
  });

  it('an expired token never subsequently becomes redeemable as real time continues to advance', async () => {
    const store = createMemorySingleUseTokenStore();
    const issuedAt = new Date('2026-01-01T00:00:00.000Z');
    const issued = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS, now: issuedAt });

    const afterExpiry = new Date(issued.expiresAt.getTime() + 1);
    const firstAttempt = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE, now: afterExpiry });
    expect(firstAttempt.outcome).toBe('expired');

    // Expiry must not have consumed the token (nothing was written) — but it
    // must ALSO never become redeemable again as real time keeps advancing.
    const laterStill = new Date(issued.expiresAt.getTime() + 10_000);
    const secondAttempt = await redeemSingleUseToken(store, issued.rawToken, { purpose: PURPOSE, now: laterStill });
    expect(secondAttempt.outcome).toBe('expired');
  });
});

describe('invalidateAllFor', () => {
  it('retires outstanding tokens for that subject+purpose only, leaves other subjects/purposes alone, and is idempotent; a retired token reads already-consumed, not not-found', async () => {
    const store = createMemorySingleUseTokenStore();
    const target = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: SUBJECT, ttlMs: TTL_MS });
    const otherSubject = await issueSingleUseToken(store, { purpose: PURPOSE, subjectId: 'user-2', ttlMs: TTL_MS });
    const otherPurpose = await issueSingleUseToken(store, { purpose: 'invite', subjectId: SUBJECT, ttlMs: TTL_MS });

    await store.invalidateAllFor(SUBJECT, PURPOSE);
    await store.invalidateAllFor(SUBJECT, PURPOSE); // idempotent — must not throw or double-act

    const targetResult = await redeemSingleUseToken(store, target.rawToken, { purpose: PURPOSE });
    expect(targetResult.outcome).toBe('already-consumed'); // not-found would betray deletion

    const otherSubjectResult = await redeemSingleUseToken(store, otherSubject.rawToken, { purpose: PURPOSE });
    expect(otherSubjectResult.outcome).toBe('redeemed');

    const otherPurposeResult = await redeemSingleUseToken(store, otherPurpose.rawToken, { purpose: 'invite' });
    expect(otherPurposeResult.outcome).toBe('redeemed');
  });
});

describe('SingleUseTokenStore.issue invariants', () => {
  it('rejects a duplicate tokenHash', async () => {
    const store = createMemorySingleUseTokenStore();
    const record = {
      id: crypto.randomUUID(),
      purpose: PURPOSE,
      subjectId: SUBJECT,
      tokenHash: hashOpaqueToken('some-raw-token'),
      expiresAt: new Date(Date.now() + TTL_MS),
      consumedAt: null,
    };
    await store.issue(record);
    await expect(store.issue({ ...record, id: crypto.randomUUID() })).rejects.toThrow(/duplicate/i);
  });

  it('rejects issuing a record with a non-null consumedAt', async () => {
    const store = createMemorySingleUseTokenStore();
    await expect(
      store.issue({
        id: crypto.randomUUID(),
        purpose: PURPOSE,
        subjectId: SUBJECT,
        tokenHash: hashOpaqueToken('some-raw-token'),
        expiresAt: new Date(Date.now() + TTL_MS),
        consumedAt: new Date(),
      }),
    ).rejects.toThrow(/consumed/i);
  });
});

describe('type-level: SingleUseTokenStore is a satisfiable port', () => {
  it('createMemorySingleUseTokenStore satisfies the SingleUseTokenStore interface', () => {
    const store: SingleUseTokenStore = createMemorySingleUseTokenStore();
    expect(store).toBeDefined();
  });
});
