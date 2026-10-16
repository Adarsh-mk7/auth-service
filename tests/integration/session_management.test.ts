import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { REFRESH_TOKEN_COOKIE_NAME } from '../../src/utils/cookie';

describe('Session Management & Revocation', () => {
  let repos: RepositoryContainer;
  let app: any;

  beforeEach(async () => {
    repos = createInMemoryRepositories();
    app = createApp(repos);

    // Register user
    await request(app).post('/api/auth/register').send({
      name: 'Session Tester',
      email: 'session@example.com',
      password: 'SecurePassword123!',
    });
  });

  it('tracks multiple active sessions across different devices', async () => {
    // Device 1 Login
    const device1Res = await request(app)
      .post('/api/auth/login')
      .set('User-Agent', 'Safari on MacOS')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });
    const device1Token = device1Res.body.data.accessToken;
    const device1Cookie = device1Res.headers['set-cookie'];

    // Device 2 Login
    const device2Res = await request(app)
      .post('/api/auth/login')
      .set('User-Agent', 'Chrome on Windows')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });

    // Request active sessions using Device 1 credentials
    const sessionsRes = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${device1Token}`)
      .set('Cookie', device1Cookie);

    expect(sessionsRes.status).toBe(200);
    expect(sessionsRes.body.success).toBe(true);
    expect(sessionsRes.body.data.sessions).toHaveLength(2);

    const userAgents = sessionsRes.body.data.sessions.map((s: any) => s.userAgent);
    expect(userAgents).toContain('Safari on MacOS');
    expect(userAgents).toContain('Chrome on Windows');

    // Current session is correctly flagged
    const current = sessionsRes.body.data.sessions.find((s: any) => s.isCurrentSession);
    expect(current).toBeDefined();
    expect(current.userAgent).toBe('Safari on MacOS');
  });

  it('POST /api/auth/logout revokes current session without affecting other devices', async () => {
    // Device 1 Login
    const dev1 = await request(app)
      .post('/api/auth/login')
      .set('User-Agent', 'Device 1')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });

    // Device 2 Login
    const dev2 = await request(app)
      .post('/api/auth/login')
      .set('User-Agent', 'Device 2')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });

    // Device 1 logs out
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', dev1.headers['set-cookie']);

    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body.success).toBe(true);

    // Refreshing Device 1 token now fails
    const dev1Refresh = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', dev1.headers['set-cookie']);
    expect(dev1Refresh.status).toBe(401);

    // Device 2 is untouched and can still refresh
    const dev2Refresh = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', dev2.headers['set-cookie']);
    expect(dev2Refresh.status).toBe(200);
  });

  it('POST /api/auth/logout-all revokes all active sessions for the user', async () => {
    // Device 1 Login
    const dev1 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });

    // Device 2 Login
    const dev2 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'session@example.com', password: 'SecurePassword123!' });

    // Logout all sessions using Device 1 token
    const logoutAllRes = await request(app)
      .post('/api/auth/logout-all')
      .set('Authorization', `Bearer ${dev1.body.data.accessToken}`);

    expect(logoutAllRes.status).toBe(200);
    expect(logoutAllRes.body.success).toBe(true);

    // Neither Device 1 nor Device 2 can refresh anymore
    const dev1Refresh = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', dev1.headers['set-cookie']);
    expect(dev1Refresh.status).toBe(401);

    const dev2Refresh = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', dev2.headers['set-cookie']);
    expect(dev2Refresh.status).toBe(401);

    // Active sessions list is now empty
    const sessionsRes = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${dev1.body.data.accessToken}`);
    expect(sessionsRes.body.data.sessions).toHaveLength(0);
  });
});
