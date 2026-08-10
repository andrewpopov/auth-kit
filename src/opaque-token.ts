import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Single-use opaque tokens (password reset, invite set-password, email change).
// Only the SHA-256 HASH is ever persisted; the raw token lives only in the
// emailed URL. These are the raw, STATELESS PRIMITIVES only — generate, hash,
// constant-time verify. Nothing here makes a token actually single-use; that
// is a storage-backed property, provided by the issue -> store -> atomic
// consume lifecycle in `single-use-token.ts` (an injected
// `SingleUseTokenStore` port, mirroring `RefreshTokenStore.rotate()` below).
// (cairn + bewks had literal copies of the primitives in
// lib/auth/resetToken.ts.)
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
