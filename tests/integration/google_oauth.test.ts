import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { Role } from '@prisma/client';
import { REFRESH_TOKEN_COOKIE_NAME } from '../../src/utils/cookie';

describe('Google OAuth 2.0 Integration & Account Linking Policy', () => {
  let repos: RepositoryContainer;
  let app: any;

  beforeEach(() => {
    repos = createInMemoryRepositories();
    app = createApp(repos);
  });

  describe('Unconfigured Environment Behavior', () => {
    it('returns 503 when Google credentials are not configured instead of crashing', async () => {
      const res = await request(app).get('/api/auth/google');
      expect(res.status).toBe(503);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Google OAuth is not configured');
    });
  });

  describe('Callback CSRF State Protection', () => {
    it('rejects callback with 403 when state parameter is missing', async () => {
      const res = await request(app).get('/api/auth/google/callback');
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('CSRF verification failed');
    });

    it('rejects callback with 403 when state parameter does not match cookie', async () => {
      const res = await request(app)
        .get('/api/auth/google/callback?state=attacker_state_123')
        .set('Cookie', 'oauth_state=victim_state_456');

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('CSRF verification failed');
    });

    it('handles provider error (e.g. user cancelled consent) with 400', async () => {
      const res = await request(app).get('/api/auth/google/callback?error=access_denied');
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('access_denied');
    });
  });

  describe('Account Linking and Token Issuance Policy', () => {
    const validState = 'secure_random_state_value';

    it('creates new user account and links OAuth on first sign in', async () => {
      const mockProfile = {
        id: 'google-sub-1001',
        email: 'newgoogleuser@example.com',
        name: 'Google User',
        isEmailVerified: true,
      };

      const res = await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe('newgoogleuser@example.com');
      expect(res.body.data.user.isEmailVerified).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();

      // Refresh cookie set
      const cookies = res.headers['set-cookie'];
      expect(cookies.some((c: string) => c.startsWith(`${REFRESH_TOKEN_COOKIE_NAME}=`))).toBe(true);

      // Verify OAuth link in repository
      const linked = await repos.oauthAccounts.findByProvider('google', 'google-sub-1001');
      expect(linked).toBeDefined();
      expect(linked?.userId).toBe(res.body.data.user.id);
    });

    it('authenticates returning user with existing linked OAuth account', async () => {
      const mockProfile = {
        id: 'google-sub-1002',
        email: 'returning@example.com',
        name: 'Returning Google User',
        isEmailVerified: true,
      };

      // First sign in
      await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      // Second sign in
      const res = await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe('returning@example.com');
      expect(res.body.data.accessToken).toBeDefined();
    });

    it('safely links OAuth account when user exists with a VERIFIED email', async () => {
      // Create local user with verified email
      const existingUser = await repos.users.create({
        email: 'verified_local@example.com',
        name: 'Verified Local User',
        passwordHash: 'hash',
        role: Role.USER,
        isEmailVerified: true,
      });

      const mockProfile = {
        id: 'google-sub-1003',
        email: 'verified_local@example.com',
        name: 'Google Profile Name',
        isEmailVerified: true,
      };

      const res = await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.id).toBe(existingUser.id);

      const linked = await repos.oauthAccounts.findByProvider('google', 'google-sub-1003');
      expect(linked?.userId).toBe(existingUser.id);
    });

    it('REJECTS auto-linking when local account email is UNVERIFIED to prevent account takeover', async () => {
      // Create local user with UNVERIFIED email
      await repos.users.create({
        email: 'unverified_local@example.com',
        name: 'Unverified Local User',
        passwordHash: 'hash',
        role: Role.USER,
        isEmailVerified: false,
      });

      const mockProfile = {
        id: 'google-sub-1004',
        email: 'unverified_local@example.com',
        name: 'Attacker Impersonation',
        isEmailVerified: true,
      };

      const res = await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('verify your email before linking');
    });

    it('rejects Google profile with unverified email', async () => {
      const mockProfile = {
        id: 'google-sub-1005',
        email: 'unverified_google@example.com',
        name: 'Unverified Google',
        isEmailVerified: false,
      };

      const res = await request(app)
        .get(`/api/auth/google/callback?state=${validState}&mock_profile=${encodeURIComponent(JSON.stringify(mockProfile))}`)
        .set('Cookie', `oauth_state=${validState}`);

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('email is not verified');
    });
  });
});
