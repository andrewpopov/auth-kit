import { describe, expect, it, vi } from 'vitest';
import {
  createGoogleAuthorizationUrl,
  createOAuthState,
  createPkcePair,
  exchangeGoogleAuthorizationCode,
  externalIdentityFromVerifiedGoogleClaims,
  googleEmailAuthority,
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
    expect(externalIdentityFromVerifiedGoogleClaims(valid, 'client')).toMatchObject({ issuer: 'https://accounts.google.com', subject: 'subject-1', email: 'owner@example.test', emailAuthority: 'asserted' });
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, iss: 'https://evil.test' }, 'client')).toBeNull();
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, aud: 'other' }, 'client')).toBeNull();
    expect(externalIdentityFromVerifiedGoogleClaims({ ...valid, sub: '' }, 'client')).toBeNull();
  });

  it('produces emailAuthority hosted for a gmail.com address through the full adapter', () => {
    const claims = { iss: 'https://accounts.google.com', aud: 'client', sub: 'subject-1', email: 'owner@gmail.com', email_verified: true, name: 'Owner' };
    expect(externalIdentityFromVerifiedGoogleClaims(claims, 'client')).toMatchObject({ email: 'owner@gmail.com', emailAuthority: 'hosted' });
  });

  it('produces emailAuthority hosted for an hd-bearing Workspace claim through the full adapter', () => {
    const claims = { iss: 'https://accounts.google.com', aud: 'client', sub: 'subject-1', email: 'owner@workspace-domain.test', email_verified: true, hd: 'workspace-domain.test', name: 'Owner' };
    expect(externalIdentityFromVerifiedGoogleClaims(claims, 'client')).toMatchObject({ email: 'owner@workspace-domain.test', emailAuthority: 'hosted' });
  });

  it('exchanges a code only through an injected cryptographic ID-token verifier', async () => {
    const verifier = { verify: vi.fn().mockResolvedValue({ iss: 'accounts.google.com', aud: 'client', sub: 'subject-1', email: 'owner@example.test', email_verified: true }) };
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id_token: 'signed-token' }) });
    const identity = await exchangeGoogleAuthorizationCode({ code: 'code', clientId: 'client', clientSecret: 'secret', redirectUri: 'https://app.test/callback', verifier, fetchImpl });
    expect(identity).toMatchObject({ subject: 'subject-1', emailAuthority: 'asserted' });
    expect(verifier.verify).toHaveBeenCalledWith('signed-token', 'client');
  });
});

describe('googleEmailAuthority', () => {
  it('a gmail.com address maps to hosted', () => {
    expect(googleEmailAuthority('owner@gmail.com', true, undefined)).toBe('hosted');
  });

  it('a googlemail.com address (legacy Google-hosted alias) maps to hosted', () => {
    expect(googleEmailAuthority('owner@googlemail.com', true, undefined)).toBe('hosted');
  });

  it('a non-empty hd string maps to hosted, regardless of the email domain', () => {
    expect(googleEmailAuthority('owner@workspace-domain.test', true, 'workspace-domain.test')).toBe('hosted');
  });

  it('an empty (whitespace-only) hd string does NOT count as hosted — falls to asserted', () => {
    expect(googleEmailAuthority('owner@workspace-domain.test', true, '   ')).toBe('asserted');
  });

  it('a non-string hd (number or object) does NOT count as hosted — falls to asserted', () => {
    expect(googleEmailAuthority('owner@workspace-domain.test', true, 12345)).toBe('asserted');
    expect(googleEmailAuthority('owner@workspace-domain.test', true, { domain: 'workspace-domain.test' })).toBe('asserted');
  });

  it('email_verified false with hd present still maps to none', () => {
    expect(googleEmailAuthority('owner@workspace-domain.test', false, 'workspace-domain.test')).toBe('none');
  });

  it('an unverified plain address maps to none', () => {
    expect(googleEmailAuthority('owner@example.test', false, undefined)).toBe('none');
  });

  it('an uppercase gmail address maps to hosted — the function normalizes defensively rather than trusting the caller', () => {
    expect(googleEmailAuthority('Owner@GMAIL.COM', true, undefined)).toBe('hosted');
  });

  it('a gmail address with leading/trailing whitespace maps to hosted — the function normalizes defensively rather than trusting the caller', () => {
    expect(googleEmailAuthority(' owner@gmail.com ', true, undefined)).toBe('hosted');
    expect(googleEmailAuthority('owner@gmail.com ', true, undefined)).toBe('hosted');
  });
});
