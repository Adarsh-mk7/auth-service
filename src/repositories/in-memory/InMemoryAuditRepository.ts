import { AuditEvent } from '@prisma/client';
import { IAuditRepository, CreateAuditLogData } from '../interfaces';
import crypto from 'crypto';

export class InMemoryAuditRepository implements IAuditRepository {
  private events: AuditEvent[] = [];

  async log(data: CreateAuditLogData): Promise<AuditEvent> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      userId: data.userId ?? null,
      action: data.action,
      ipAddress: data.ipAddress ?? null,
      userAgent: data.userAgent ?? null,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null,
      createdAt: new Date(),
    };

    this.events.push(event);
    return { ...event };
  }

  async listByUser(userId: string, limit = 50): Promise<AuditEvent[]> {
    return this.events
      .filter((e) => e.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit)
      .map((e) => ({ ...e }));
  }

  getAll(): AuditEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events = [];
  }
}
