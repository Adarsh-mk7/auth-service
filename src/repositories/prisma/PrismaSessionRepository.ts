import { PrismaClient, Session, User } from '@prisma/client';
import { ISessionRepository, CreateSessionData } from '../interfaces';

export class PrismaSessionRepository implements ISessionRepository {
  constructor(private prisma: PrismaClient) {}

  async create(data: CreateSessionData): Promise<Session> {
    return this.prisma.session.create({
      data: {
        userId: data.userId,
        tokenHash: data.tokenHash,
        familyId: data.familyId,
        generation: data.generation ?? 1,
        expiresAt: data.expiresAt,
        userAgent: data.userAgent ?? null,
        ipAddress: data.ipAddress ?? null,
      },
    });
  }

  async findByTokenHash(tokenHash: string): Promise<(Session & { user?: User }) | null> {
    return this.prisma.session.findUnique({
      where: { tokenHash },
      include: { user: true },
    });
  }

  async findById(id: string): Promise<Session | null> {
    return this.prisma.session.findUnique({
      where: { id },
    });
  }

  async findActiveByUserId(userId: string): Promise<Session[]> {
    return this.prisma.session.findMany({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastUsedAt: 'desc' },
    });
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    return this.prisma.session.update({
      where: { id },
      data,
    });
  }

  async revokeFamily(familyId: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { familyId },
      data: { isRevoked: true },
    });
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { userId },
      data: { isRevoked: true },
    });
  }

  async delete(id: string): Promise<void> {
    await this.prisma.session.delete({
      where: { id },
    });
  }
}
