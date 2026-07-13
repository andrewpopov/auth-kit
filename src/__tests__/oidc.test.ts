import { describe, expect, it, vi } from 'vitest';
import {
  createGoogleAuthorizationUrl,
  createOAuthState,
  createPkcePair,
  exchangeGoogleAuthorizationCode,
  externalIdentityFromVerifiedGoogleClaims,
  requireSameBrowserOAuthState,
  verifyOAuthState,
} from '../index';

const secret = 'test-state-secret';

describe('OIDC proof primitives', () => {
  it('signs, validates, and expires an OAuth intent', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const state = createOAuthState({ secret, intent: { purpose: 'link', accountId: 'user-1' }, now, ttlMs: 1000 });
    expect(verifyOAuthState(state, secret, new Date(now.getTime() + 999))).toMatchObject({ purpose: 'link', accountId: 'user-1' });
    expect(verifyOAuthState(state, secret, new Date(now.getTime() + 1000))).toBeNull();
    expect(verifyOAuthState(`${state}x`, secret, now)).toBeNull();
  });

  it.each([0, -1, 1.5])('rejects invalid OAuth state TTLs: %s', (ttlMs) => {
    expect(() => createOAuthState({ secret, intent: { purpose: 'login' }, ttlMs })).toThrow(/ttlMs/);
  });

  it('canaries same-browser binding: a valid signed state without its cookie is rejected', () => {
    const state = createOAuthState({ secret, intent: { purpose: 'login' } });
    expect(requireSameBrowserOAuthState(state, undefined, secret)).toBeNull();
    expect(requireSameBrowserOAuthState(state, `${state}x`, secret)).toBeNull();
    expect(requireSameBrowserOAuthState(state, state, secret)).toMatchObject({ purpose: 'login' });
  });

  it('creates an RFC 7636 S256 PKCE pair and includes it in Google authorization', () => {
    const pkce = createPkcePair();
    expect(pkce.verifier.length).toBeGreaterThan(43);
    expect(pkce.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    const url = new URL(createGoogleAuthorizationUrl({ clientId: 'client', redirectUri: 'https://app.test/callback', state: 'state', pkce }));
    expect(url.origin).toBe('https://accounts.google.com');
    expect(url.searchParams.get('code_challenge')).toBe(pkce.challenge);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('accepts only verified Google issuer, audience, and stable subject claims', () => {
    const valid = { iss: 'https://accounts.google.com', aud: 'client', sub: 'subject-1', email: 'Owner@Example.test', email_verified: true, name: 'Owner' };
    expect(externalIdentityFromVerifiedGoogleClaims(valid, 'client')).toMatchObject({ issuer: 'https://accounts.google.com', subject: 'subject-1', email: 'owner@example.test', emailVerified: true });
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, iss: 'https://evil.test' }, 'client')).toBeNull();
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, aud: 'other' }, 'client')).toBeNull();
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, sub: '' }, 'client')).toBeNull();
  });

  it('exchanges a code only through an injected cryptographic ID-token verifier', async () => {
    const verifier = { verify: vi.fn().mockResolvedValue({ iss: 'accounts.google.com', aud: 'client', sub: 'subject-1', email: 'owner@example.test', email_verified: true }) };
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id_token: 'signed-token' }) });
    const identity = await exchangeGoogleAuthorizationCode({ code: 'code', clientId: 'client', clientSecret: 'secret', redirectUri: 'https://app.test/callback', verifier, fetchImpl });
    expect(identity).toMatchObject({ subject: 'subject-1', emailVerified: true });
    expect(verifier.verify).toHaveBeenCalledWith('signed-token', 'client');
  });
});
