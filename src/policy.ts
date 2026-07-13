/** Thrown when a security-sensitive duration or bcrypt cost is invalid. */
export class AuthPolicyError extends Error {
  constructor(readonly code: 'bcrypt-rounds' | 'ttl' | 'grace', message: string) {
    super(message);
    this.name = 'AuthPolicyError';
  }
}

export function requirePositiveTtl(ttlMs: number, name = 'ttlMs'): void {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new AuthPolicyError('ttl', `${name} must be a positive integer number of milliseconds`);
}

export function requireGraceMs(graceMs: number): void {
  if (!Number.isSafeInteger(graceMs) || graceMs < 0) throw new AuthPolicyError('grace', 'graceMs must be a non-negative integer number of milliseconds');
}

export function requireBcryptRounds(rounds: number): void {
  if (!Number.isSafeInteger(rounds) || rounds < 4 || rounds > 31) throw new AuthPolicyError('bcrypt-rounds', 'bcrypt rounds must be an integer between 4 and 31');
}
