import { describe, it, expect } from 'vitest';
import { TokenUtil } from '../../src/utils/token';
import { UserContext } from '../../src/types';
import jwt from 'jsonwebtoken';
import { config } from '../../src/config/environment';

describe('Token Utility', () => {
  const mockUser: UserContext = {
    id: 'test-user-id-123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'USER',
    isEmailVerified: true,
  };

  it('signs and verifies a valid JWT access token', () => {
    const token = TokenUtil.signAccessToken(mockUser);
    expect(typeof token).toBe('string');

    const decoded = TokenUtil.verifyAccessToken(token);
    expect(decoded.id).toBe(mockUser.id);
    expect(decoded.email).toBe(mockUser.email);
    expect(decoded.name).toBe(mockUser.name);
    expect(decoded.role).toBe(mockUser.role);
    expect(decoded.isEmailVerified).toBe(true);
  });

  it('rejects an expired access token', () => {
    // Generate an already expired token
    const expiredToken = jwt.sign(mockUser, config.JWT_ACCESS_SECRET, {
      expiresIn: '-1s',
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });

    expect(() => TokenUtil.verifyAccessToken(expiredToken)).toThrow('Access token has expired');
  });

  it('rejects a malformed or improperly signed token', () => {
    expect(() => TokenUtil.verifyAccessToken('not.a.valid.jwt')).toThrow('Invalid access token');

    // Signed with wrong secret
    const badSecretToken = jwt.sign(mockUser, 'wrong_secret_1234567890123456', {
      expiresIn: '15m',
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });

    expect(() => TokenUtil.verifyAccessToken(badSecretToken)).toThrow('Invalid access token');
  });

  it('generates secure random hex tokens and computes deterministic SHA-256 hashes', () => {
    const token = TokenUtil.generateSecureRandomToken(32);
    expect(token).toHaveLength(64); // 32 bytes = 64 hex characters

    const hash1 = TokenUtil.hashToken(token);
    const hash2 = TokenUtil.hashToken(token);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });
});
