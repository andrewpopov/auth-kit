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
