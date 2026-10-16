import { Session, User } from '@prisma/client';
import { ISessionRepository, CreateSessionData, IUserRepository } from '../interfaces';
import crypto from 'crypto';

export class InMemorySessionRepository implements ISessionRepository {
  private sessions: Map<string, Session> = new Map();
  private userRepo?: IUserRepository;

  constructor(userRepo?: IUserRepository) {
    this.userRepo = userRepo;
  }

  setUserRepository(userRepo: IUserRepository) {
    this.userRepo = userRepo;
  }

  async create(data: CreateSessionData): Promise<Session> {
    const existing = await this.findByTokenHash(data.tokenHash);
    if (existing) {
      throw new Error(`Unique constraint failed on the fields: (tokenHash)`);
    }

    const now = new Date();
    const session: Session = {
      id: crypto.randomUUID(),
      userId: data.userId,
      tokenHash: data.tokenHash,
      familyId: data.familyId,
      generation: data.generation ?? 1,
      isRevoked: false,
      userAgent: data.userAgent ?? null,
      ipAddress: data.ipAddress ?? null,
      expiresAt: data.expiresAt,
      createdAt: now,
      lastUsedAt: now,
    };

    this.sessions.set(session.id, session);
    return { ...session };
  }

  async findByTokenHash(tokenHash: string): Promise<(Session & { user?: User }) | null> {
    for (const session of this.sessions.values()) {
      if (session.tokenHash === tokenHash) {
        let user: User | undefined;
        if (this.userRepo) {
          const found = await this.userRepo.findById(session.userId);
          if (found) user = found;
        }
        return { ...session, user };
      }
    }
    return null;
  }

  async findById(id: string): Promise<Session | null> {
    const session = this.sessions.get(id);
    return session ? { ...session } : null;
  }

  async findActiveByUserId(userId: string): Promise<Session[]> {
    const now = new Date();
    const active: Session[] = [];
    for (const session of this.sessions.values()) {
      if (session.userId === userId && !session.isRevoked && session.expiresAt > now) {
        active.push({ ...session });
      }
    }
    return active.sort((a, b) => b.lastUsedAt.getTime() - a.lastUsedAt.getTime());
  }

  async update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session> {
    const session = this.sessions.get(id);
    if (!session) {
      throw new Error(`Session with id ${id} not found`);
    }

    const updatedSession: Session = {
      ...session,
      ...data,
      lastUsedAt: data.lastUsedAt || new Date(),
    };
    this.sessions.set(id, updatedSession);
    return { ...updatedSession };
  }

  async revokeFamily(familyId: string): Promise<void> {
    for (const [id, session] of this.sessions.entries()) {
      if (session.familyId === familyId) {
        this.sessions.set(id, { ...session, isRevoked: true });
      }
    }
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.set(id, { ...session, isRevoked: true });
      }
    }
  }

  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  clear(): void {
    this.sessions.clear();
  }
}
