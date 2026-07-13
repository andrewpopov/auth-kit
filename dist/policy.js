"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthPolicyError = void 0;
exports.requirePositiveTtl = requirePositiveTtl;
exports.requireGraceMs = requireGraceMs;
exports.requireBcryptRounds = requireBcryptRounds;
/** Thrown when a security-sensitive duration or bcrypt cost is invalid. */
class AuthPolicyError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'AuthPolicyError';
    }
}
exports.AuthPolicyError = AuthPolicyError;
function requirePositiveTtl(ttlMs, name = 'ttlMs') {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1)
        throw new AuthPolicyError('ttl', `${name} must be a positive integer number of milliseconds`);
}
function requireGraceMs(graceMs) {
    if (!Number.isSafeInteger(graceMs) || graceMs < 0)
        throw new AuthPolicyError('grace', 'graceMs must be a non-negative integer number of milliseconds');
}
function requireBcryptRounds(rounds) {
    if (!Number.isSafeInteger(rounds) || rounds < 4 || rounds > 31)
        throw new AuthPolicyError('bcrypt-rounds', 'bcrypt rounds must be an integer between 4 and 31');
}
