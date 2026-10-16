import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { getEmailService, DevelopmentEmailService } from '../../src/services/email/email.service';
import { TokenUtil } from '../../src/utils/token';

describe('Password Management (Forgot, Reset & Change)', () => {
  let repos: RepositoryContainer;
  let app: any;
  let emailService: DevelopmentEmailService;

  beforeEach(async () => {
    repos = createInMemoryRepositories();
    app = createApp(repos);
    emailService = getEmailService() as DevelopmentEmailService;
    emailService.clear();

    // Register a user
    await request(app).post('/api/auth/register').send({
      name: 'Adarsh User',
      email: 'resetme@example.com',
      password: 'OldPassword123!',
    });
  });

  describe('POST /api/auth/forgot-password', () => {
    it('returns generic response and sends email when user exists', async () => {
      const res = await request(app).post('/api/auth/forgot-password').send({
        email: 'resetme@example.com',
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('password reset instructions have been sent');

      const emails = emailService.getSentEmails();
      expect(emails.length).toBe(1);
      expect(emails[0].to).toBe('resetme@example.com');
      expect(emails[0].token).toBeDefined();
    });

    it('returns identical generic response when email does not exist (no enumeration)', async () => {
      const res = await request(app).post('/api/auth/forgot-password').send({
        email: 'nonexistent@example.com',
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('password reset instructions have been sent');

      const emails = emailService.getSentEmails();
      expect(emails.length).toBe(0);
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('successfully resets password, invalidates all sessions, and rejects token reuse', async () => {
      // 1. Log in to establish an active session before reset
      const loginBefore = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      const cookieBefore = loginBefore.headers['set-cookie'];

      // 2. Request forgot password
      await request(app).post('/api/auth/forgot-password').send({
        email: 'resetme@example.com',
      });
      const token = emailService.getSentEmails()[0].token!;

      // 3. Reset password
      const resetRes = await request(app).post('/api/auth/reset-password').send({
        token,
        newPassword: 'BrandNewPassword123!',
      });

      expect(resetRes.status).toBe(200);
      expect(resetRes.body.success).toBe(true);
      expect(resetRes.body.message).toContain('successfully reset');

      // 4. Old password no longer works
      const oldLogin = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      expect(oldLogin.status).toBe(401);

      // 5. New password works
      const newLogin = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'BrandNewPassword123!',
      });
      expect(newLogin.status).toBe(200);

      // 6. Old session is invalidated and cannot refresh
      const refreshAttempt = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', cookieBefore);
      expect(refreshAttempt.status).toBe(401);

      // 7. Token replay rejection: using the reset token again must fail
      const replayRes = await request(app).post('/api/auth/reset-password').send({
        token,
        newPassword: 'AnotherNewPassword123!',
      });
      expect(replayRes.status).toBe(400);
      expect(replayRes.body.message).toContain('already been used');
    });

    it('rejects expired reset token', async () => {
      const user = await repos.users.findByEmail('resetme@example.com');
      const expiredRawToken = TokenUtil.generateSecureRandomToken();
      const expiredTokenHash = TokenUtil.hashToken(expiredRawToken);

      // Create an expired token manually in repository
      await repos.passwordResets.create({
        userId: user!.id,
        tokenHash: expiredTokenHash,
        expiresAt: new Date(Date.now() - 1000 * 60), // Expired 1 minute ago
      });

      const res = await request(app).post('/api/auth/reset-password').send({
        token: expiredRawToken,
        newPassword: 'ValidPassword123!',
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('expired');
    });

    it('rejects invalid or non-existent reset token', async () => {
      const res = await request(app).post('/api/auth/reset-password').send({
        token: 'this_is_a_completely_fake_reset_token_12345678',
        newPassword: 'ValidPassword123!',
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Invalid or expired');
    });
  });

  describe('POST /api/auth/change-password', () => {
    it('successfully changes password and invalidates other sessions', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      const token = loginRes.body.data.accessToken;

      const changeRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({
          currentPassword: 'OldPassword123!',
          newPassword: 'ChangedPassword987!',
        });

      expect(changeRes.status).toBe(200);
      expect(changeRes.body.success).toBe(true);

      // Old password fails
      const oldLogin = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      expect(oldLogin.status).toBe(401);

      // New password succeeds
      const newLogin = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'ChangedPassword987!',
      });
      expect(newLogin.status).toBe(200);
    });

    it('rejects change password when current password is wrong', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      const token = loginRes.body.data.accessToken;

      const changeRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({
          currentPassword: 'IncorrectPassword!',
          newPassword: 'ChangedPassword987!',
        });

      expect(changeRes.status).toBe(401);
      expect(changeRes.body.message).toContain('Current password is incorrect');
    });

    it('rejects new password identical to current password', async () => {
      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'resetme@example.com',
        password: 'OldPassword123!',
      });
      const token = loginRes.body.data.accessToken;

      const changeRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({
          currentPassword: 'OldPassword123!',
          newPassword: 'OldPassword123!',
        });

      expect(changeRes.status).toBe(400);
      expect(changeRes.body.message).toBe('Validation failed');
    });
  });
});
