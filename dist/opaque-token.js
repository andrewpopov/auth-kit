"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashResetToken = exports.generateResetToken = void 0;
exports.generateOpaqueToken = generateOpaqueToken;
exports.hashOpaqueToken = hashOpaqueToken;
exports.verifyOpaqueToken = verifyOpaqueToken;
const crypto_1 = __importDefault(require("crypto"));
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
