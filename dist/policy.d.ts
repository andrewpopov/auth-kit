/** Thrown when a security-sensitive duration or bcrypt cost is invalid. */
export declare class AuthPolicyError extends Error {
    readonly code: 'bcrypt-rounds' | 'ttl' | 'grace';
    constructor(code: 'bcrypt-rounds' | 'ttl' | 'grace', message: string);
}
export declare function requirePositiveTtl(ttlMs: number, name?: string): void;
export declare function requireGraceMs(graceMs: number): void;
export declare function requireBcryptRounds(rounds: number): void;
