import { describe, it, expect, beforeEach } from 'vitest';
import { createInMemoryRepositories } from '../../src/repositories';
import { Role } from '../../src/repositories/interfaces';

describe('Repository Layer (In-Memory Implementation)', () => {
  let repos: ReturnType<typeof createInMemoryRepositories>;

  beforeEach(() => {
    repos = createInMemoryRepositories();
  });

  describe('UserRepository', () => {
    it('creates and finds a user by id and email', async () => {
      const user = await repos.users.create({
        email: 'test@example.com',
        name: 'Test User',
        passwordHash: 'hashed_password',
        role: Role.USER,
      });

      expect(user.id).toBeDefined();
      expect(user.email).toBe('test@example.com');
      expect(user.role).toBe(Role.USER);

      const foundById = await repos.users.findById(user.id);
      expect(foundById?.email).toBe('test@example.com');

      const foundByEmail = await repos.users.findByEmail('TEST@example.com');
      expect(foundByEmail?.id).toBe(user.id);
    });

    it('rejects duplicate email creation', async () => {
      await repos.users.create({
        email: 'duplicate@example.com',
        name: 'First User',
      });

      await expect(
        repos.users.create({
          email: 'duplicate@example.com',
          name: 'Second User',
        })
      ).rejects.toThrow();
    });

    it('updates user attributes', async () => {
      const user = await repos.users.create({
        email: 'update@example.com',
        name: 'Original Name',
      });

      const updated = await repos.users.update(user.id, {
        name: 'Updated Name',
        role: Role.ADMIN,
      });

      expect(updated.name).toBe('Updated Name');
      expect(updated.role).toBe(Role.ADMIN);
    });
  });

  describe('SessionRepository', () => {
    it('manages sessions and handles token family revocation', async () => {
      const user = await repos.users.create({
        email: 'session@example.com',
        name: 'Session User',
      });

      const expiresAt = new Date(Date.now() + 1000 * 60 * 60);
      const session1 = await repos.sessions.create({
        userId: user.id,
        tokenHash: 'hash_1',
        familyId: 'family_123',
        generation: 1,
        expiresAt,
      });

      const session2 = await repos.sessions.create({
        userId: user.id,
        tokenHash: 'hash_2',
        familyId: 'family_123',
        generation: 2,
        expiresAt,
      });

      let activeSessions = await repos.sessions.findActiveByUserId(user.id);
      expect(activeSessions.length).toBe(2);

      // Revoke the entire family
      await repos.sessions.revokeFamily('family_123');

      activeSessions = await repos.sessions.findActiveByUserId(user.id);
      expect(activeSessions.length).toBe(0);

      const s1 = await repos.sessions.findById(session1.id);
      const s2 = await repos.sessions.findById(session2.id);
      expect(s1?.isRevoked).toBe(true);
      expect(s2?.isRevoked).toBe(true);
    });
  });

  describe('PasswordResetRepository', () => {
    it('creates and marks reset tokens as used', async () => {
      const user = await repos.users.create({
        email: 'reset@example.com',
        name: 'Reset User',
      });

      const token = await repos.passwordResets.create({
        userId: user.id,
        tokenHash: 'reset_hash_123',
        expiresAt: new Date(Date.now() + 1000 * 60 * 15),
      });

      expect(token.usedAt).toBeNull();

      const found = await repos.passwordResets.findByTokenHash('reset_hash_123');
      expect(found?.id).toBe(token.id);

      await repos.passwordResets.markAsUsed(token.id);
      const updated = await repos.passwordResets.findByTokenHash('reset_hash_123');
      expect(updated?.usedAt).not.toBeNull();
    });
  });

  describe('AuditRepository', () => {
    it('logs audit events and queries them', async () => {
      await repos.audits.log({
        userId: 'user_1',
        action: 'LOGIN_SUCCESS',
        ipAddress: '127.0.0.1',
        metadata: { browser: 'Chrome' },
      });

      const logs = await repos.audits.listByUser('user_1');
      expect(logs.length).toBe(1);
      expect(logs[0].action).toBe('LOGIN_SUCCESS');
      expect(logs[0].ipAddress).toBe('127.0.0.1');
    });
  });
});
