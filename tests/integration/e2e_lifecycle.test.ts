import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { REFRESH_TOKEN_COOKIE_NAME } from '../../src/utils/cookie';

describe('End-to-End User Lifecycle & API Documentation', () => {
  let repos: RepositoryContainer;
  let app: any;

  beforeEach(() => {
    repos = createInMemoryRepositories();
    app = createApp(repos);
  });

  it('completes the entire end-to-end user lifecycle securely', async () => {
    // 1. User Registration
    const regRes = await request(app).post('/api/auth/register').send({
      name: 'Lifecycle Tester',
      email: 'lifecycle@example.com',
      password: 'InitialPassword123!',
    });
    expect(regRes.status).toBe(201);
    expect(regRes.body.data.user.email).toBe('lifecycle@example.com');

    // 2. User Login
    const loginRes = await request(app).post('/api/auth/login').send({
      email: 'lifecycle@example.com',
      password: 'InitialPassword123!',
    });
    expect(loginRes.status).toBe(200);
    const accessToken = loginRes.body.data.accessToken;
    const initialCookie = loginRes.headers['set-cookie'];
    expect(accessToken).toBeDefined();
    expect(initialCookie).toBeDefined();

    // 3. Access Protected Route /api/auth/me
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(meRes.status).toBe(200);
    expect(meRes.body.data.user.email).toBe('lifecycle@example.com');

    // 4. View Active Sessions
    const sessionsRes = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', initialCookie);
    expect(sessionsRes.status).toBe(200);
    expect(sessionsRes.body.data.sessions.length).toBe(1);

    // 5. Rotate Refresh Token
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', initialCookie);
    expect(refreshRes.status).toBe(200);
    const newAccessToken = refreshRes.body.data.accessToken;
    const newCookie = refreshRes.headers['set-cookie'];
    expect(newAccessToken).not.toBe(accessToken);

    // 6. Change Password
    const changePwRes = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${newAccessToken}`)
      .send({
        currentPassword: 'InitialPassword123!',
        newPassword: 'BrandNewSecurePassword789$',
      });
    expect(changePwRes.status).toBe(200);

    // 7. Verify Old Password Fails and New Password Succeeds
    const oldLoginAttempt = await request(app).post('/api/auth/login').send({
      email: 'lifecycle@example.com',
      password: 'InitialPassword123!',
    });
    expect(oldLoginAttempt.status).toBe(401);

    const newLoginAttempt = await request(app).post('/api/auth/login').send({
      email: 'lifecycle@example.com',
      password: 'BrandNewSecurePassword789$',
    });
    expect(newLoginAttempt.status).toBe(200);

    // 8. Log out current session
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', newLoginAttempt.headers['set-cookie']);
    expect(logoutRes.status).toBe(200);

    // 9. Verify OpenAPI docs endpoint responds
    const docsRes = await request(app).get('/api/docs/');
    expect([200, 301, 302]).toContain(docsRes.status);
  });
});
