import crypto from 'crypto';
import type { EmailAuthority, ExternalIdentity } from './identity';
import { requirePositiveTtl } from './policy';

const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);

export type OAuthIntent =
  | { purpose: 'login' }
  | { purpose: 'link'; accountId: string };

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

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function decodeBase64Url(value: string): Buffer | null {
  try { return Buffer.from(value, 'base64url'); } catch { return null; }
}

function signature(input: string, secret: string | Buffer): string {
  return crypto.createHmac('sha256', secret).update(input).digest('base64url');
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Create a signed, short-lived OAuth intent. Put the exact returned value in an HttpOnly callback-scoped cookie. */
export function createOAuthState(options: CreateOAuthStateOptions): string {
  const now = options.now ?? new Date();
  const ttlMs = options.ttlMs ?? 10 * 60 * 1000;
  requirePositiveTtl(ttlMs);
  const payload: OAuthStatePayload = {
    kind: 'auth-kit-oauth-state',
    nonce: crypto.randomUUID(),
    issuedAt: now.getTime(),
    expiresAt: now.getTime() + ttlMs,
    ...options.intent,
  };
  const encoded = base64Url(JSON.stringify(payload));
  return `${encoded}.${signature(encoded, options.secret)}`;
}

/** Verify state signature and shape. Adapters must additionally use {@link requireSameBrowserOAuthState}. */
export function verifyOAuthState(state: string, secret: string | Buffer, now = new Date()): OAuthStatePayload | null {
  const [encoded, provided, extra] = state.split('.');
  if (!encoded || !provided || extra || !safeEqual(signature(encoded, secret), provided)) return null;
  const decoded = decodeBase64Url(encoded);
  if (!decoded) return null;
  let payload: unknown;
  try { payload = JSON.parse(decoded.toString('utf8')); } catch { return null; }
  if (!payload || typeof payload !== 'object') return null;
  const value = payload as Record<string, unknown>;
  if (
    value.kind !== 'auth-kit-oauth-state' ||
    typeof value.nonce !== 'string' ||
    typeof value.issuedAt !== 'number' ||
    typeof value.expiresAt !== 'number' ||
    value.expiresAt <= now.getTime() ||
    (value.purpose !== 'login' && value.purpose !== 'link') ||
    (value.purpose === 'link' && typeof value.accountId !== 'string')
  ) return null;
  return value.purpose === 'link'
    ? { kind: 'auth-kit-oauth-state', nonce: value.nonce as string, issuedAt: value.issuedAt as number, expiresAt: value.expiresAt as number, purpose: 'link', accountId: value.accountId as string }
    : { kind: 'auth-kit-oauth-state', nonce: value.nonce as string, issuedAt: value.issuedAt as number, expiresAt: value.expiresAt as number, purpose: 'login' };
}

/**
 * Enforce the same-browser ceremony: callback state must be byte-for-byte the
 * value retained in the initiating browser's HttpOnly cookie, then validly
 * signed and unexpired. A signed URL sent to another browser therefore fails.
 */
export function requireSameBrowserOAuthState(
  callbackState: string | undefined,
  cookieState: string | undefined,
  secret: string | Buffer,
  now?: Date,
): OAuthStatePayload | null {
  if (!callbackState || !cookieState || !safeEqual(callbackState, cookieState)) return null;
  return verifyOAuthState(callbackState, secret, now);
}

export interface PkcePair {
  verifier: string;
  challenge: string;
  method: 'S256';
}

/** Generate a high-entropy RFC 7636 PKCE verifier and S256 challenge. */
export function createPkcePair(): PkcePair {
  const verifier = crypto.randomBytes(48).toString('base64url');
  return {
    verifier,
    challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    method: 'S256',
  };
}

export interface GoogleAuthorizationUrlOptions {
  clientId: string;
  redirectUri: string;
  state: string;
  pkce?: Pick<PkcePair, 'challenge' | 'method'>;
  scopes?: string[];
  prompt?: 'select_account' | 'consent';
}

/** Build the Google OpenID Connect authorization URL. It contains no user-storage logic. */
export function createGoogleAuthorizationUrl(options: GoogleAuthorizationUrlOptions): string {
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

export interface GoogleIdTokenClaims {
  iss?: unknown;
  aud?: unknown;
  sub?: unknown;
  email?: unknown;
  email_verified?: unknown;
  hd?: unknown;
  name?: unknown;
  picture?: unknown;
}

/**
 * Map Google claims to an {@link EmailAuthority}. Google is authoritative for
 * an address only when it HOSTS that address right now:
 *
 * - `@gmail.com` / `@googlemail.com` (the latter is a legacy alias for the
 *   same hosted mailbox space and must be treated identically).
 * - Workspace: `hd` present, PRESENCE-ONLY. Google's documented rule for `hd`
 *   is presence, not equality against the email's domain — do NOT "tighten"
 *   this to `hd === domain`. Requiring equality would falsely reject
 *   Workspace alias-domain users while buying no real security: a Workspace
 *   admin controls the domain's mail either way, alias or primary.
 *
 * Anything else that is merely `email_verified: true` is `'asserted'`: Google
 * vouched for the address at some point in the past, but a personal Google
 * account can be created against (and keep verified status for) a
 * third-party address that later changes hands, so that assertion is not
 * proof of PRESENT mailbox control.
 */
export function googleEmailAuthority(rawEmail: string | null, emailVerified: boolean, hd: unknown): EmailAuthority {
  // Exported, and hand-called by consumers who won't all have pre-normalized
  // the address — normalize defensively here rather than trust the caller,
  // so `Owner@GMAIL.COM` or a trailing-space address still hits the suffix
  // checks below instead of silently under-classifying as 'asserted'. The
  // parameter is deliberately NOT named `normalizedEmail`: that would imply a
  // precondition callers must meet, and the whole point is that they need not.
  const email = rawEmail?.trim().toLowerCase() ?? null;
  if (!emailVerified || !email) return 'none';
  if (email.endsWith('@gmail.com') || email.endsWith('@googlemail.com')) return 'hosted';
  if (typeof hd === 'string' && hd.trim().length > 0) return 'hosted';
  return 'asserted';
}

/**
 * Convert claims returned by a cryptographically verified Google ID-token
 * verifier into the package's provider-neutral identity. Signature/JWK
 * verification is intentionally injected: apps may use google-auth-library,
 * jose, Passport, or their framework's validated provider result.
 */
export function externalIdentityFromVerifiedGoogleClaims(claims: GoogleIdTokenClaims, clientId: string): ExternalIdentity | null {
  if (!GOOGLE_ISSUERS.has(String(claims.iss)) || claims.aud !== clientId || typeof claims.sub !== 'string' || claims.sub.length === 0) return null;
  const email = typeof claims.email === 'string' && claims.email.trim() ? claims.email.trim().toLowerCase() : null;
  const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
  return {
    issuer: 'https://accounts.google.com',
    subject: claims.sub,
    email,
    emailAuthority: googleEmailAuthority(email, emailVerified, claims.hd),
    name: typeof claims.name === 'string' ? claims.name : null,
    picture: typeof claims.picture === 'string' ? claims.picture : null,
  };
}

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
export async function exchangeGoogleAuthorizationCode(options: GoogleCodeExchangeOptions): Promise<ExternalIdentity | null> {
  const body = new URLSearchParams({
    code: options.code,
    client_id: options.clientId,
    client_secret: options.clientSecret,
    redirect_uri: options.redirectUri,
    grant_type: 'authorization_code',
  });
  if (options.codeVerifier) body.set('code_verifier', options.codeVerifier);
  const response = await (options.fetchImpl ?? fetch)('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
  });
  if (!response.ok) return null;
  const token = await response.json() as { id_token?: unknown };
  if (typeof token.id_token !== 'string') return null;
  const claims = await options.verifier.verify(token.id_token, options.clientId);
  return externalIdentityFromVerifiedGoogleClaims(claims, options.clientId);
}
