import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { REFRESH_TOKEN_COOKIE_NAME } from '../../src/utils/cookie';
import { AuthService } from '../../src/services/auth.service';

describe('Authentication, Tokens & Refresh Rotation', () => {
  let repos: RepositoryContainer;
  let app: any;

  beforeEach(async () => {
    AuthService.clearGraceTokens();
    repos = createInMemoryRepositories();
    app = createApp(repos);

    // Register a standard user
    await request(app).post('/api/auth/register').send({
      name: 'Adarsh Developer',
      email: 'user@example.com',
      password: 'StrongPassword123!',
    });
  });

  describe('POST /api/auth/login', () => {
    it('successfully logs in with valid credentials and sets HTTP-only refresh cookie', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: 'user@example.com',
        password: 'StrongPassword123!',
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(res.body.data.user.email).toBe('user@example.com');

      // Check cookie
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      const refreshCookie = cookies.find((c: string) => c.startsWith(`${REFRESH_TOKEN_COOKIE_NAME}=`));
      expect(refreshCookie).toBeDefined();
      expect(refreshCookie).toContain('HttpOnly');
    });

    it('rejects invalid password with generic 401 error', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: 'user@example.com',
        password: 'WrongPassword999!',
      });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid email or password');
    });

    it('rejects non-existent email with identical generic 401 error (no enumeration)', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: 'unknown@example.com',
        password: 'SomePassword123!',
      });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid email or password');
    });
  });

  describe('GET /api/auth/me (Protected Route)', () => {
    it('returns user profile when presented with valid access token', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'user@example.com',
        password: 'StrongPassword123!',
      });
      const token = loginRes.body.data.accessToken;

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe('user@example.com');
      expect(res.body.data.user.name).toBe('Adarsh Developer');
    });

    it('returns 401 when Authorization header is missing', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('token missing');
    });

    it('returns 401 when token is invalid or corrupted', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid.token.payload');
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Invalid access token');
    });
  });

  describe('POST /api/auth/refresh (Token Rotation & Reuse Detection)', () => {
    it('rotates refresh token and returns new access token', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'user@example.com',
        password: 'StrongPassword123!',
      });

      const initialCookie = loginRes.headers['set-cookie'];
      const initialAccessToken = loginRes.body.data.accessToken;

      const refreshRes = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', initialCookie);

      expect(refreshRes.status).toBe(200);
      expect(refreshRes.body.success).toBe(true);
      expect(refreshRes.body.data.accessToken).toBeDefined();
      expect(refreshRes.body.data.accessToken).not.toBe(initialAccessToken);

      const rotatedCookie = refreshRes.headers['set-cookie'];
      expect(rotatedCookie).toBeDefined();
    });

    it('detects token reuse and revokes entire session family', async () => {
      // 1. Log in
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'user@example.com',
        password: 'StrongPassword123!',
      });
      const originalCookie = loginRes.headers['set-cookie'];

      // Extract raw token string
      const cookieStr = originalCookie.find((c: string) => c.startsWith(`${REFRESH_TOKEN_COOKIE_NAME}=`));
      const rawToken = cookieStr.split(';')[0].split('=')[1];

      // 2. Legitimate user rotates token
      const refreshRes = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', originalCookie);
      expect(refreshRes.status).toBe(200);

      // Clear the 15s grace cache to simulate an attacker reusing the old token outside the grace window
      AuthService.clearGraceTokens();

      // Attacker attempts to reuse the old/rotated token
      const reuseRes = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: rawToken });

      expect(reuseRes.status).toBe(401);
      expect(reuseRes.body.message).toContain('revoked');

      // Verify that the active session in that family was also revoked!
      const activeSessions = await repos.sessions.findActiveByUserId(loginRes.body.data.user.id);
      expect(activeSessions.length).toBe(0);
    });
  });
});
