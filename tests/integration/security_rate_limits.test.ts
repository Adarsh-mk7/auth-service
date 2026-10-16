import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app';
import { createInMemoryRepositories, RepositoryContainer } from '../../src/repositories';
import { MemoryRateLimiterStore, setRateLimiterStore } from '../../src/middleware/rateLimiter';

describe('API Security Controls & Rate Limiting', () => {
  let repos: RepositoryContainer;
  let app: any;
  let store: MemoryRateLimiterStore;

  beforeEach(() => {
    store = new MemoryRateLimiterStore();
    setRateLimiterStore(store);
    repos = createInMemoryRepositories();
    // Configure rate limit of 5 for this specific suite
    app = createApp({ repos, rateLimits: { loginMax: 5 } });
  });

  describe('Rate Limiting Enforcement', () => {
    it('returns 429 Too Many Requests when endpoint threshold is exceeded', async () => {
      // 5 requests allowed, 6th should be rejected
      for (let i = 0; i < 5; i++) {
        const res = await request(app).post('/api/auth/login').send({
          email: 'wrong@example.com',
          password: 'WrongPassword123!',
        });
        expect(res.status).toBe(401); // Failed login but within rate limit
        expect(res.headers).toHaveProperty('ratelimit-limit');
      }

      // 6th attempt triggers 429 Too Many Requests
      const blockedRes = await request(app).post('/api/auth/login').send({
        email: 'wrong@example.com',
        password: 'WrongPassword123!',
      });

      expect(blockedRes.status).toBe(429);
      expect(blockedRes.body.success).toBe(false);
      expect(blockedRes.body.message).toContain('Too many');
      expect(blockedRes.headers).toHaveProperty('retry-after');
      expect(blockedRes.headers['ratelimit-remaining']).toBe('0');
    });
  });

  describe('Malformed JSON and Payload Limits', () => {
    it('handles malformed JSON gracefully with 400 Bad Request', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('{"invalid_json": true,');

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid JSON payload');
    });

    it('rejects oversized request payloads exceeding 10kb limit', async () => {
      const hugeString = 'a'.repeat(12 * 1024); // 12 KB payload
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Huge Payload User',
          email: 'huge@example.com',
          password: 'Password123!',
          extra: hugeString,
        });

      expect(res.status).toBe(413); // Payload Too Large
    });
  });

  describe('Security Headers (Helmet)', () => {
    it('includes essential security headers on responses', async () => {
      const res = await request(app).get('/health');

      expect(res.headers).toHaveProperty('x-content-type-options', 'nosniff');
      expect(res.headers).toHaveProperty('x-frame-options');
      expect(res.headers).toHaveProperty('content-security-policy');
    });
  });

  describe('Undefined Routes (404)', () => {
    it('returns consistent JSON 404 for non-existent endpoints', async () => {
      const res = await request(app).get('/api/does-not-exist');

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('not found');
    });
  });
});
