"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createOAuthState = createOAuthState;
exports.verifyOAuthState = verifyOAuthState;
exports.requireSameBrowserOAuthState = requireSameBrowserOAuthState;
exports.createPkcePair = createPkcePair;
exports.createGoogleAuthorizationUrl = createGoogleAuthorizationUrl;
exports.externalIdentityFromVerifiedGoogleClaims = externalIdentityFromVerifiedGoogleClaims;
exports.exchangeGoogleAuthorizationCode = exchangeGoogleAuthorizationCode;
const crypto_1 = __importDefault(require("crypto"));
const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
function base64Url(value) {
    return Buffer.from(value).toString('base64url');
}
function decodeBase64Url(value) {
    try {
        return Buffer.from(value, 'base64url');
    }
    catch {
        return null;
    }
}
function signature(input, secret) {
    return crypto_1.default.createHmac('sha256', secret).update(input).digest('base64url');
}
function safeEqual(left, right) {
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && crypto_1.default.timingSafeEqual(a, b);
}
/** Create a signed, short-lived OAuth intent. Put the exact returned value in an HttpOnly callback-scoped cookie. */
function createOAuthState(options) {
    const now = options.now ?? new Date();
    const payload = {
        kind: 'auth-kit-oauth-state',
        nonce: crypto_1.default.randomUUID(),
        issuedAt: now.getTime(),
        expiresAt: now.getTime() + (options.ttlMs ?? 10 * 60 * 1000),
        ...options.intent,
    };
    const encoded = base64Url(JSON.stringify(payload));
    return `${encoded}.${signature(encoded, options.secret)}`;
}
/** Verify state signature and shape. Adapters must additionally use {@link requireSameBrowserOAuthState}. */
function verifyOAuthState(state, secret, now = new Date()) {
    const [encoded, provided, extra] = state.split('.');
    if (!encoded || !provided || extra || !safeEqual(signature(encoded, secret), provided))
        return null;
    const decoded = decodeBase64Url(encoded);
    if (!decoded)
        return null;
    let payload;
    try {
        payload = JSON.parse(decoded.toString('utf8'));
    }
    catch {
        return null;
    }
    if (!payload || typeof payload !== 'object')
        return null;
    const value = payload;
    if (value.kind !== 'auth-kit-oauth-state' ||
        typeof value.nonce !== 'string' ||
        typeof value.issuedAt !== 'number' ||
        typeof value.expiresAt !== 'number' ||
        value.expiresAt <= now.getTime() ||
        (value.purpose !== 'login' && value.purpose !== 'link') ||
        (value.purpose === 'link' && typeof value.accountId !== 'string'))
        return null;
    return value.purpose === 'link'
        ? { kind: 'auth-kit-oauth-state', nonce: value.nonce, issuedAt: value.issuedAt, expiresAt: value.expiresAt, purpose: 'link', accountId: value.accountId }
        : { kind: 'auth-kit-oauth-state', nonce: value.nonce, issuedAt: value.issuedAt, expiresAt: value.expiresAt, purpose: 'login' };
}
/**
 * Enforce the same-browser ceremony: callback state must be byte-for-byte the
 * value retained in the initiating browser's HttpOnly cookie, then validly
 * signed and unexpired. A signed URL sent to another browser therefore fails.
 */
function requireSameBrowserOAuthState(callbackState, cookieState, secret, now) {
    if (!callbackState || !cookieState || !safeEqual(callbackState, cookieState))
        return null;
    return verifyOAuthState(callbackState, secret, now);
}
/** Generate a high-entropy RFC 7636 PKCE verifier and S256 challenge. */
function createPkcePair() {
    const verifier = crypto_1.default.randomBytes(48).toString('base64url');
    return {
        verifier,
        challenge: crypto_1.default.createHash('sha256').update(verifier).digest('base64url'),
        method: 'S256',
    };
}
/** Build the Google OpenID Connect authorization URL. It contains no user-storage logic. */
function createGoogleAuthorizationUrl(options) {
    const query = new URLSearchParams({
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: 'code',
        scope: (options.scopes ?? ['openid', 'email', 'profile']).join(' '),
        state: options.state,
        prompt: options.prompt ?? 'select_account',
    });
    if (options.pkce) {
        query.set('code_challenge', options.pkce.challenge);
        query.set('code_challenge_method', options.pkce.method);
    }
    return `https://accounts.google.com/o/oauth2/v2/auth?${query}`;
}
/**
 * Convert claims returned by a cryptographically verified Google ID-token
 * verifier into the package's provider-neutral identity. Signature/JWK
 * verification is intentionally injected: apps may use google-auth-library,
 * jose, Passport, or their framework's validated provider result.
 */
function externalIdentityFromVerifiedGoogleClaims(claims, clientId) {
    if (!GOOGLE_ISSUERS.has(String(claims.iss)) || claims.aud !== clientId || typeof claims.sub !== 'string' || claims.sub.length === 0)
        return null;
    const email = typeof claims.email === 'string' && claims.email.trim() ? claims.email.trim().toLowerCase() : null;
    const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
    return {
        issuer: 'https://accounts.google.com',
        subject: claims.sub,
        email,
        emailVerified,
        name: typeof claims.name === 'string' ? claims.name : null,
        picture: typeof claims.picture === 'string' ? claims.picture : null,
    };
}
/** Exchange an authorization code and return a cryptographically verified, provider-neutral Google identity. */
async function exchangeGoogleAuthorizationCode(options) {
    const body = new URLSearchParams({
        code: options.code,
        client_id: options.clientId,
        client_secret: options.clientSecret,
        redirect_uri: options.redirectUri,
        grant_type: 'authorization_code',
    });
    if (options.codeVerifier)
        body.set('code_verifier', options.codeVerifier);
    const response = await (options.fetchImpl ?? fetch)('https://oauth2.googleapis.com/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
    if (!response.ok)
        return null;
    const token = await response.json();
    if (typeof token.id_token !== 'string')
        return null;
    const claims = await options.verifier.verify(token.id_token, options.clientId);
    return externalIdentityFromVerifiedGoogleClaims(claims, options.clientId);
}
