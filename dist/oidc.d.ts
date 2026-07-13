import type { ExternalIdentity } from './identity';
export type OAuthIntent = {
    purpose: 'login';
} | {
    purpose: 'link';
    accountId: string;
};
export type OAuthStatePayload = OAuthIntent & {
    kind: 'auth-kit-oauth-state';
    nonce: string;
    issuedAt: number;
    expiresAt: number;
};
export interface CreateOAuthStateOptions {
    secret: string | Buffer;
    intent: OAuthIntent;
    now?: Date;
    ttlMs?: number;
}
/** Create a signed, short-lived OAuth intent. Put the exact returned value in an HttpOnly callback-scoped cookie. */
export declare function createOAuthState(options: CreateOAuthStateOptions): string;
/** Verify state signature and shape. Adapters must additionally use {@link requireSameBrowserOAuthState}. */
export declare function verifyOAuthState(state: string, secret: string | Buffer, now?: Date): OAuthStatePayload | null;
/**
 * Enforce the same-browser ceremony: callback state must be byte-for-byte the
 * value retained in the initiating browser's HttpOnly cookie, then validly
 * signed and unexpired. A signed URL sent to another browser therefore fails.
 */
export declare function requireSameBrowserOAuthState(callbackState: string | undefined, cookieState: string | undefined, secret: string | Buffer, now?: Date): OAuthStatePayload | null;
export interface PkcePair {
    verifier: string;
    challenge: string;
    method: 'S256';
}
/** Generate a high-entropy RFC 7636 PKCE verifier and S256 challenge. */
export declare function createPkcePair(): PkcePair;
export interface GoogleAuthorizationUrlOptions {
    clientId: string;
    redirectUri: string;
    state: string;
    pkce?: Pick<PkcePair, 'challenge' | 'method'>;
    scopes?: string[];
    prompt?: 'select_account' | 'consent';
}
/** Build the Google OpenID Connect authorization URL. It contains no user-storage logic. */
export declare function createGoogleAuthorizationUrl(options: GoogleAuthorizationUrlOptions): string;
export interface GoogleIdTokenClaims {
    iss?: unknown;
    aud?: unknown;
    sub?: unknown;
    email?: unknown;
    email_verified?: unknown;
    name?: unknown;
    picture?: unknown;
}
/**
 * Convert claims returned by a cryptographically verified Google ID-token
 * verifier into the package's provider-neutral identity. Signature/JWK
 * verification is intentionally injected: apps may use google-auth-library,
 * jose, Passport, or their framework's validated provider result.
 */
export declare function externalIdentityFromVerifiedGoogleClaims(claims: GoogleIdTokenClaims, clientId: string): ExternalIdentity | null;
export interface GoogleIdTokenVerifier {
    /** Must verify the ID-token signature and return its claims, or throw/reject. */
    verify(idToken: string, audience: string): Promise<GoogleIdTokenClaims>;
}
export interface GoogleCodeExchangeOptions {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    codeVerifier?: string;
    verifier: GoogleIdTokenVerifier;
    fetchImpl?: typeof fetch;
}
/** Exchange an authorization code and return a cryptographically verified, provider-neutral Google identity. */
export declare function exchangeGoogleAuthorizationCode(options: GoogleCodeExchangeOptions): Promise<ExternalIdentity | null>;
