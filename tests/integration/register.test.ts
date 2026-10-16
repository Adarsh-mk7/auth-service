import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';

describe('POST /api/auth/register', () => {
  let repos: RepositoryContainer;
  let app: any;

  beforeEach(() => {
    repos = createInMemoryRepositories();
    app = createApp(repos);
  });

  it('successfully registers a user with valid credentials', async () => {
    const payload = {
      name: 'Adarsh Developer',
      email: 'Developer@Example.COM',
      password: 'StrongPassword123!',
    };

    const res = await request(app)
      .post('/api/auth/register')
      .send(payload);

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe('User registered successfully');
    expect(res.body.data.user).toBeDefined();
    expect(res.body.data.user.email).toBe('developer@example.com');
    expect(res.body.data.user.name).toBe('Adarsh Developer');
    expect(res.body.data.user.role).toBe('USER');
    expect(res.body.data.user.isEmailVerified).toBe(false);
    expect(res.body.data.user).not.toHaveProperty('password');
    expect(res.body.data.user).not.toHaveProperty('passwordHash');

    // Verify audit log
    const auditLogs = await repos.audits.listByUser(res.body.data.user.id);
    expect(auditLogs.length).toBe(1);
    expect(auditLogs[0].action).toBe('USER_REGISTER');
  });

  it('rejects registration with duplicate email address', async () => {
    const payload = {
      name: 'First User',
      email: 'unique@example.com',
      password: 'ValidPassword123!',
    };

    const firstRes = await request(app).post('/api/auth/register').send(payload);
    expect(firstRes.status).toBe(201);

    const duplicateRes = await request(app).post('/api/auth/register').send({
      name: 'Second User',
      email: 'UNIQUE@example.com',
      password: 'AnotherValidPassword123!',
    });

    expect(duplicateRes.status).toBe(409);
    expect(duplicateRes.body.success).toBe(false);
    expect(duplicateRes.body.message).toContain('already exists');
  });

  it('rejects invalid email address format', async () => {
    const res = await request(app).post('/api/auth/register').send({
      name: 'Invalid Email User',
      email: 'not-an-email',
      password: 'ValidPassword123!',
    });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.errors).toBeDefined();
    expect(res.body.errors.some((e: any) => e.field === 'email')).toBe(true);
  });

  it('rejects weak passwords failing the password policy', async () => {
    // Too short
    let res = await request(app).post('/api/auth/register').send({
      name: 'User',
      email: 'user1@example.com',
      password: 'Sh1!',
    });
    expect(res.status).toBe(400);

    // Missing uppercase
    res = await request(app).post('/api/auth/register').send({
      name: 'User',
      email: 'user2@example.com',
      password: 'lowercase123!',
    });
    expect(res.status).toBe(400);

    // Missing special character
    res = await request(app).post('/api/auth/register').send({
      name: 'User',
      email: 'user3@example.com',
      password: 'NoSpecial123',
    });
    expect(res.status).toBe(400);

    // Missing numbers
    res = await request(app).post('/api/auth/register').send({
      name: 'User',
      email: 'user4@example.com',
      password: 'NoNumbersHere!',
    });
    expect(res.status).toBe(400);
  });

  it('rejects payload missing required fields', async () => {
    const res = await request(app).post('/api/auth/register').send({
      name: 'Missing Password User',
    });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});
