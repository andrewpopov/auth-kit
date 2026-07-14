import { describe, it, expect, vi } from 'vitest';
import crypto from 'crypto';
import bcryptjs from 'bcryptjs';
import {
  generateOpaqueToken,
  hashOpaqueToken,
  verifyOpaqueToken,
  generateResetToken,
  hashResetToken,
  prehashPassword,
  createPasswordHasher,
  AuthPolicyError,
  DEFAULT_BCRYPT_ROUNDS,
  type BcryptLike,
} from '../index';

describe('opaque tokens', () => {
  it('generates 64-hex tokens, unique per call', () => {
    const t = generateOpaqueToken();
    expect(t).toMatch(/^[0-9a-f]{64}$/);
    expect(t).not.toBe(generateOpaqueToken());
  });

  it('hashes to sha256 hex, stable', () => {
    const t = generateOpaqueToken();
    const expected = crypto.createHash('sha256').update(t).digest('hex');
    expect(hashOpaqueToken(t)).toBe(expected);
    expect(hashOpaqueToken(t)).toBe(hashOpaqueToken(t));
  });

  it('verifies a raw token against its stored hash (constant-time), rejects wrong/mismatched-length', () => {
    const raw = generateOpaqueToken();
    const stored = hashOpaqueToken(raw);
    expect(verifyOpaqueToken(raw, stored)).toBe(true);
    expect(verifyOpaqueToken(generateOpaqueToken(), stored)).toBe(false);
    expect(verifyOpaqueToken(raw, 'short')).toBe(false);
  });

  it('reset-token aliases are the same primitive', () => {
    expect(generateResetToken).toBe(generateOpaqueToken);
    expect(hashResetToken).toBe(hashOpaqueToken);
  });
});

describe('prehashPassword', () => {
  it('is a fixed 64-hex digest within bcrypt\'s 72-byte limit', () => {
    const long = 'x'.repeat(200);
    const digest = prehashPassword(long);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.byteLength(digest)).toBe(64);
    // Distinct long passwords that share a 72-byte prefix hash differently.
    expect(prehashPassword('x'.repeat(72) + 'A')).not.toBe(prehashPassword('x'.repeat(72) + 'B'));
  });
});

describe('createPasswordHasher (logic, fake bcrypt)', () => {
  const fake = (): BcryptLike => ({
    hash: vi.fn(async (data: string, rounds: number) => `H(${data},${rounds})`),
    compare: vi.fn(async (data: string, hash: string) => hash === `H(${data},12)`),
    hashSync: vi.fn((data: string, rounds: number) => `H(${data},${rounds})`),
  });

  it('defaults to 12 rounds and no pre-hash', async () => {
    const bcrypt = fake();
    const hasher = createPasswordHasher({ bcrypt });
    expect(hasher.rounds).toBe(DEFAULT_BCRYPT_ROUNDS);
    expect(await hasher.hash('pw')).toBe('H(pw,12)');
    expect(bcrypt.hash).toHaveBeenCalledWith('pw', 12);
  });

  it('applies pre-hash on both hash and verify when enabled', async () => {
    const bcrypt = fake();
    const hasher = createPasswordHasher({ bcrypt, preHash: true });
    const digest = prehashPassword('pw');
    await hasher.hash('pw');
    expect(bcrypt.hash).toHaveBeenCalledWith(digest, 12);
    await hasher.verify('pw', 'somehash');
    expect(bcrypt.compare).toHaveBeenCalledWith(digest, 'somehash');
  });

  it('honors a custom cost', async () => {
    const bcrypt = fake();
    const hasher = createPasswordHasher({ bcrypt, rounds: 14 });
    expect(hasher.rounds).toBe(14);
    await hasher.hash('pw');
    expect(bcrypt.hash).toHaveBeenCalledWith('pw', 14);
  });

  it.each([3, 32, 12.5, Number.NaN])('rejects invalid bcrypt rounds: %s', (rounds) => {
    expect(() => createPasswordHasher({ bcrypt: fake(), rounds })).toThrow(AuthPolicyError);
  });

  it('caches the dummy hash and computes it via hashSync with the same policy', () => {
    const bcrypt = fake();
    const hasher = createPasswordHasher({ bcrypt, preHash: true });
    const d1 = hasher.dummyHash();
    const d2 = hasher.dummyHash();
    expect(d1).toBe(d2);
    expect(bcrypt.hashSync).toHaveBeenCalledTimes(1);
    expect(bcrypt.hashSync).toHaveBeenCalledWith(prehashPassword('absent-user-timing-padding'), 12);
  });
});

describe('createPasswordHasher (real bcryptjs round-trip)', () => {
  it('hash then verify succeeds; a wrong password fails', async () => {
    const hasher = createPasswordHasher({ bcrypt: bcryptjs as unknown as BcryptLike, rounds: 8 });
    const hash = await hasher.hash('correct horse battery staple');
    expect(hash).toMatch(/^\$2[aby]\$0?8\$/);
    expect(await hasher.verify('correct horse battery staple', hash)).toBe(true);
    expect(await hasher.verify('wrong', hash)).toBe(false);
  });

  it('the dummy hash is a real bcrypt hash no real password matches', async () => {
    const hasher = createPasswordHasher({ bcrypt: bcryptjs as unknown as BcryptLike, rounds: 8 });
    const dummy = hasher.dummyHash();
    expect(dummy).toMatch(/^\$2[aby]\$/);
    expect(await hasher.verify('any password', dummy)).toBe(false);
  });

  it('pre-hash and plain modes are NOT cross-compatible (migration guard)', async () => {
    const plain = createPasswordHasher({ bcrypt: bcryptjs as unknown as BcryptLike, rounds: 8, preHash: false });
    const pre = createPasswordHasher({ bcrypt: bcryptjs as unknown as BcryptLike, rounds: 8, preHash: true });
    const plainHash = await plain.hash('pw');
    // A pre-hash verifier feeds sha256(pw), which won't match a hash of raw "pw".
    expect(await pre.verify('pw', plainHash)).toBe(false);
  });
});
