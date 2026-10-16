import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { Role } from '@prisma/client';
import { PasswordUtil } from '../../src/utils/password';

describe('Role-Based Access Control & Ownership Enforcement', () => {
  let repos: RepositoryContainer;
  let app: any;

  let regularUser: any;
  let moderatorUser: any;
  let adminUser: any;

  let userToken: string;
  let modToken: string;
  let adminToken: string;

  beforeEach(async () => {
    repos = createInMemoryRepositories();
    app = createApp(repos);

    const hash = await PasswordUtil.hash('Password123!');

    // Create 3 users with different roles
    regularUser = await repos.users.create({
      email: 'user@example.com',
      name: 'Regular User',
      passwordHash: hash,
      role: Role.USER,
      isEmailVerified: true,
    });

    moderatorUser = await repos.users.create({
      email: 'mod@example.com',
      name: 'Moderator User',
      passwordHash: hash,
      role: Role.MODERATOR,
      isEmailVerified: true,
    });

    adminUser = await repos.users.create({
      email: 'admin@example.com',
      name: 'Admin User',
      passwordHash: hash,
      role: Role.ADMIN,
      isEmailVerified: true,
    });

    // Obtain access tokens
    const loginUser = await request(app).post('/api/auth/login').send({
      email: 'user@example.com',
      password: 'Password123!',
    });
    userToken = loginUser.body.data.accessToken;

    const loginMod = await request(app).post('/api/auth/login').send({
      email: 'mod@example.com',
      password: 'Password123!',
    });
    modToken = loginMod.body.data.accessToken;

    const loginAdmin = await request(app).post('/api/auth/login').send({
      email: 'admin@example.com',
      password: 'Password123!',
    });
    adminToken = loginAdmin.body.data.accessToken;
  });

  describe('Administrative Route Protection (GET /api/admin/users)', () => {
    it('rejects unauthenticated request with 401', async () => {
      const res = await request(app).get('/api/admin/users');
      expect(res.status).toBe(401);
    });

    it('rejects USER role with 403 Forbidden', async () => {
      const res = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('Forbidden');
    });

    it('rejects MODERATOR role with 403 Forbidden', async () => {
      const res = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${modToken}`);
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('Forbidden');
    });

    it('grants access to ADMIN role with 200 OK', async () => {
      const res = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.users.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Role Modification (PATCH /api/admin/users/:id/role)', () => {
    it('allows ADMIN to promote regular user to MODERATOR', async () => {
      const res = await request(app)
        .patch(`/api/admin/users/${regularUser.id}/role`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'MODERATOR' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.role).toBe('MODERATOR');

      const updated = await repos.users.findById(regularUser.id);
      expect(updated?.role).toBe('MODERATOR');
    });

    it('prevents regular USER from changing roles', async () => {
      const res = await request(app)
        .patch(`/api/admin/users/${regularUser.id}/role`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ role: 'ADMIN' });

      expect(res.status).toBe(403);
    });

    it('prevents demotion of the sole remaining administrator', async () => {
      const res = await request(app)
        .patch(`/api/admin/users/${adminUser.id}/role`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'USER' });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('sole remaining system administrator');
    });

    it('rejects invalid role enum values', async () => {
      const res = await request(app)
        .patch(`/api/admin/users/${regularUser.id}/role`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'SUPER_USER' });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Validation failed');
    });
  });

  describe('Privilege Escalation Prevention', () => {
    it('ignores client-supplied role during registration and defaults to USER', async () => {
      const res = await request(app).post('/api/auth/register').send({
        name: 'Sneaky Attacker',
        email: 'attacker@example.com',
        password: 'Password123!',
        role: 'ADMIN', // Client attempting vertical privilege escalation
      });

      expect(res.status).toBe(201);
      expect(res.body.data.user.role).toBe('USER');

      const userInDb = await repos.users.findByEmail('attacker@example.com');
      expect(userInDb?.role).toBe('USER');
    });
  });

  describe('Resource Ownership Enforcement (GET /api/users/:id)', () => {
    it('allows a user to access their own resource', async () => {
      const res = await request(app)
        .get(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.user.id).toBe(regularUser.id);
    });

    it('prevents horizontal privilege escalation (User A cannot access User B)', async () => {
      const res = await request(app)
        .get(`/api/users/${moderatorUser.id}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('Forbidden');
    });

    it('allows ADMIN to access any user resource (override role)', async () => {
      const res = await request(app)
        .get(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.user.id).toBe(regularUser.id);
    });
  });
});
