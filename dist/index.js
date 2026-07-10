"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashResetToken = exports.generateResetToken = exports.DEFAULT_BCRYPT_ROUNDS = void 0;
exports.generateOpaqueToken = generateOpaqueToken;
exports.hashOpaqueToken = hashOpaqueToken;
exports.verifyOpaqueToken = verifyOpaqueToken;
exports.prehashPassword = prehashPassword;
exports.createPasswordHasher = createPasswordHasher;
const crypto_1 = __importDefault(require("crypto"));
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
exports.DEFAULT_BCRYPT_ROUNDS = 12;
// ---------------------------------------------------------------------------
// Single-use opaque tokens (password reset, invite set-password, email change).
// Only the SHA-256 HASH is ever persisted; the raw token lives only in the
// emailed URL. One primitive backs every such flow. (cairn + bewks had literal
// copies of this in lib/auth/resetToken.ts.)
// ---------------------------------------------------------------------------
/** Generate a random opaque token (64 lowercase hex chars, 256 bits). */
function generateOpaqueToken() {
    return crypto_1.default.randomBytes(32).toString('hex');
}
/** Hash a token for storage/comparison (SHA-256 hex). */
function hashOpaqueToken(token) {
    return crypto_1.default.createHash('sha256').update(token).digest('hex');
}
/** Constant-time check of a raw token against a stored SHA-256 hash. */
function verifyOpaqueToken(rawToken, storedHash) {
    const given = Buffer.from(hashOpaqueToken(rawToken));
    const want = Buffer.from(storedHash);
    if (given.length !== want.length)
        return false;
    return crypto_1.default.timingSafeEqual(given, want);
}
// Reset-token aliases — the historical names cairn/bewks used for the same primitive.
exports.generateResetToken = generateOpaqueToken;
exports.hashResetToken = hashOpaqueToken;
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
function prehashPassword(password) {
    return crypto_1.default.createHash('sha256').update(password).digest('hex');
}
/** Create a password hasher bound to a bcrypt implementation and policy. */
function createPasswordHasher(options) {
    const rounds = options.rounds ?? exports.DEFAULT_BCRYPT_ROUNDS;
    const prep = (password) => (options.preHash ? prehashPassword(password) : password);
    let cachedDummy = null;
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
