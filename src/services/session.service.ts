import { RepositoryContainer } from '../repositories';
import { TokenUtil } from '../utils/token';
import { Session } from '@prisma/client';
import { ForbiddenError, NotFoundError } from '../utils/errors';

export interface SessionDto {
  id: string;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: Date;
  lastUsedAt: Date;
  isCurrentSession: boolean;
}

export class SessionService {
  constructor(private repos: RepositoryContainer) {}

  async logout(
    rawRefreshToken?: string,
    userId?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    if (rawRefreshToken) {
      const tokenHash = TokenUtil.hashToken(rawRefreshToken);
      const session = await this.repos.sessions.findByTokenHash(tokenHash);

      if (session) {
        await this.repos.sessions.update(session.id, { isRevoked: true });
        await this.repos.audits.log({
          userId: session.userId,
          action: 'LOGOUT_CURRENT',
          ipAddress: ipAddress ?? null,
          userAgent: userAgent ?? null,
          metadata: { sessionId: session.id },
        });
        return;
      }
    }

    if (userId) {
      await this.repos.audits.log({
        userId,
        action: 'LOGOUT_CURRENT',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
      });
    }
  }

  async logoutAll(
    userId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    await this.repos.sessions.revokeAllForUser(userId);

    await this.repos.audits.log({
      userId,
      action: 'LOGOUT_ALL',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });
  }

  async getActiveSessions(
    userId: string,
    currentRawRefreshToken?: string
  ): Promise<SessionDto[]> {
    const sessions = await this.repos.sessions.findActiveByUserId(userId);
    const currentHash = currentRawRefreshToken ? TokenUtil.hashToken(currentRawRefreshToken) : null;

    return sessions.map((s: Session) => ({
      id: s.id,
      userAgent: s.userAgent,
      ipAddress: s.ipAddress,
      createdAt: s.createdAt,
      lastUsedAt: s.lastUsedAt,
      isCurrentSession: currentHash !== null && s.tokenHash === currentHash,
    }));
  }

  async revokeSessionById(
    userId: string,
    sessionId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const session = await this.repos.sessions.findById(sessionId);
    if (!session) {
      throw new NotFoundError('Session not found');
    }

    if (session.userId !== userId) {
      throw new ForbiddenError('You do not have permission to revoke this session');
    }

    await this.repos.sessions.update(sessionId, { isRevoked: true });

    await this.repos.audits.log({
      userId,
      action: 'REVOKE_SESSION',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: { sessionId },
    });
  }
}
