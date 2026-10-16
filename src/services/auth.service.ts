import { RepositoryContainer } from '../repositories';
import { RegisterInput, LoginInput } from '../validators/auth.validator';
import { PasswordUtil } from '../utils/password';
import { TokenUtil } from '../utils/token';
import { ConflictError, UnauthorizedError, NotFoundError } from '../utils/errors';
import { config } from '../config/environment';
import { User, Role } from '@prisma/client';
import crypto from 'crypto';

export interface UserResponseDto {
  id: string;
  email: string;
  name: string;
  role: Role;
  isEmailVerified: boolean;
  createdAt: Date;
}

export interface AuthSuccessDto {
  user: UserResponseDto;
  accessToken: string;
  refreshToken: string;
}

export const sanitizeUser = (user: User): UserResponseDto => {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    createdAt: user.createdAt,
  };
};

export class AuthService {
  // Grace period map to handle rapid concurrent refresh requests safely (prevents accidental family revocation)
  private static graceTokens = new Map<string, { newRawToken: string; newAccessToken: string; expiresAt: number }>();

  constructor(private repos: RepositoryContainer) {}

  async register(
    input: RegisterInput,
    ipAddress?: string,
    userAgent?: string
  ): Promise<UserResponseDto> {
    const normalizedEmail = input.email.trim().toLowerCase();

    // Check for existing user
    const existing = await this.repos.users.findByEmail(normalizedEmail);
    if (existing) {
      throw new ConflictError('An account with this email address already exists');
    }

    // Hash password
    const passwordHash = await PasswordUtil.hash(input.password);

    // Create user
    const user = await this.repos.users.create({
      email: normalizedEmail,
      name: input.name.trim(),
      passwordHash,
      role: Role.USER,
      isEmailVerified: false,
    });

    // Audit log
    await this.repos.audits.log({
      userId: user.id,
      action: 'USER_REGISTER',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: { email: user.email },
    });

    return sanitizeUser(user);
  }

  async login(
    input: LoginInput,
    ipAddress?: string,
    userAgent?: string
  ): Promise<AuthSuccessDto> {
    const normalizedEmail = input.email.trim().toLowerCase();

    // Query user
    const user = await this.repos.users.findByEmail(normalizedEmail);

    // Generic error to prevent user enumeration
    if (!user || !user.passwordHash) {
      await this.repos.audits.log({
        action: 'LOGIN_FAILURE',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { email: normalizedEmail, reason: 'User not found or no password hash' },
      });
      throw new UnauthorizedError('Invalid email or password');
    }

    // Verify password
    const isValidPassword = await PasswordUtil.compare(input.password, user.passwordHash);
    if (!isValidPassword) {
      await this.repos.audits.log({
        userId: user.id,
        action: 'LOGIN_FAILURE',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { email: normalizedEmail, reason: 'Password mismatch' },
      });
      throw new UnauthorizedError('Invalid email or password');
    }

    // Issue tokens
    const rawRefreshToken = TokenUtil.generateSecureRandomToken();
    const tokenHash = TokenUtil.hashToken(rawRefreshToken);
    const familyId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + config.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

    await this.repos.sessions.create({
      userId: user.id,
      tokenHash,
      familyId,
      generation: 1,
      expiresAt,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });

    const sanitizedUser = sanitizeUser(user);
    const accessToken = TokenUtil.signAccessToken(sanitizedUser);

    await this.repos.audits.log({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });

    return {
      user: sanitizedUser,
      accessToken,
      refreshToken: rawRefreshToken,
    };
  }

  async refreshToken(
    rawRefreshToken: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<AuthSuccessDto> {
    if (!rawRefreshToken) {
      throw new UnauthorizedError('Refresh token required');
    }

    const tokenHash = TokenUtil.hashToken(rawRefreshToken);

    // Check if token was recently rotated in grace period (e.g. concurrent browser tabs)
    const graceEntry = AuthService.graceTokens.get(tokenHash);
    if (graceEntry && graceEntry.expiresAt > Date.now()) {
      const activeSession = await this.repos.sessions.findByTokenHash(TokenUtil.hashToken(graceEntry.newRawToken));
      if (activeSession && !activeSession.isRevoked && activeSession.user) {
        return {
          user: sanitizeUser(activeSession.user),
          accessToken: graceEntry.newAccessToken,
          refreshToken: graceEntry.newRawToken,
        };
      }
    }

    const session = await this.repos.sessions.findByTokenHash(tokenHash);

    // If session not found -> Invalid refresh token
    if (!session) {
      throw new UnauthorizedError('Invalid refresh token');
    }

    // If session is revoked -> Token reuse incident!
    if (session.isRevoked) {
      // Revoke the entire session family immediately
      await this.repos.sessions.revokeFamily(session.familyId);

      await this.repos.audits.log({
        userId: session.userId,
        action: 'TOKEN_REUSE_DETECTED',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { familyId: session.familyId, tokenHash },
      });

      throw new UnauthorizedError('Token reuse detected. All sessions in this chain have been revoked for your security.');
    }

    // Check expiration
    if (session.expiresAt <= new Date()) {
      throw new UnauthorizedError('Refresh token has expired');
    }

    const user = session.user || (await this.repos.users.findById(session.userId));
    if (!user) {
      throw new UnauthorizedError('User account associated with this session no longer exists');
    }

    // Rotate refresh token:
    // Mark previous session as revoked (used) so any replay is caught
    await this.repos.sessions.update(session.id, {
      isRevoked: true,
      lastUsedAt: new Date(),
    });

    // Create new active session in the family
    const newRawRefreshToken = TokenUtil.generateSecureRandomToken();
    const newTokenHash = TokenUtil.hashToken(newRawRefreshToken);
    const newExpiresAt = new Date(Date.now() + config.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

    await this.repos.sessions.create({
      userId: user.id,
      tokenHash: newTokenHash,
      familyId: session.familyId,
      generation: session.generation + 1,
      expiresAt: newExpiresAt,
      ipAddress: ipAddress ?? session.ipAddress,
      userAgent: userAgent ?? session.userAgent,
    });

    const sanitizedUser = sanitizeUser(user);
    const newAccessToken = TokenUtil.signAccessToken(sanitizedUser);

    // Store in grace tokens for 15 seconds to support concurrent requests safely
    AuthService.graceTokens.set(tokenHash, {
      newRawToken: newRawRefreshToken,
      newAccessToken,
      expiresAt: Date.now() + 15000,
    });

    // Cleanup expired grace tokens
    for (const [key, val] of AuthService.graceTokens.entries()) {
      if (val.expiresAt <= Date.now()) {
        AuthService.graceTokens.delete(key);
      }
    }

    await this.repos.audits.log({
      userId: user.id,
      action: 'TOKEN_REFRESH',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: { familyId: session.familyId, generation: session.generation + 1 },
    });

    return {
      user: sanitizedUser,
      accessToken: newAccessToken,
      refreshToken: newRawRefreshToken,
    };
  }

  async getMe(userId: string): Promise<UserResponseDto> {
    const user = await this.repos.users.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    return sanitizeUser(user);
  }

  // Helper for tests to clear grace tokens
  static clearGraceTokens(): void {
    AuthService.graceTokens.clear();
  }
}
