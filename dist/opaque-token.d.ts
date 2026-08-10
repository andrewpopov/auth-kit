/** Generate a random opaque token (64 lowercase hex chars, 256 bits). */
export declare function generateOpaqueToken(): string;
/** Hash a token for storage/comparison (SHA-256 hex). */
export declare function hashOpaqueToken(token: string): string;
/** Constant-time check of a raw token against a stored SHA-256 hash. */
export declare function verifyOpaqueToken(rawToken: string, storedHash: string): boolean;
export declare const generateResetToken: typeof generateOpaqueToken;
export declare const hashResetToken: typeof hashOpaqueToken;
