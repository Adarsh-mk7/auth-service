import { PrismaClient, AuditEvent } from '@prisma/client';
import { IAuditRepository, CreateAuditLogData } from '../interfaces';

export class PrismaAuditRepository implements IAuditRepository {
  constructor(private prisma: PrismaClient) {}

  async log(data: CreateAuditLogData): Promise<AuditEvent> {
    return this.prisma.auditEvent.create({
      data: {
        userId: data.userId ?? null,
        action: data.action,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
        metadata: data.metadata ? JSON.stringify(data.metadata) : null,
      },
    });
  }

  async listByUser(userId: string, limit = 50): Promise<AuditEvent[]> {
    return this.prisma.auditEvent.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }
}
