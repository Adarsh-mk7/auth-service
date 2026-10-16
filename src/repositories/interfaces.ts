import { User, Session, PasswordResetToken, OAuthAccount, AuditEvent, Role } from '@prisma/client';

export { Role };

export interface CreateUserData {
  email: string;
  name: string;
  passwordHash?: string | null;
  role?: Role;
  isEmailVerified?: boolean;
}

export interface IUserRepository {
  create(data: CreateUserData): Promise<User>;
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  update(id: string, data: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User>;
  list(skip?: number, take?: number): Promise<{ users: User[]; total: number }>;
  delete(id: string): Promise<void>;
  count(): Promise<number>;
}

export interface CreateSessionData {
  userId: string;
  tokenHash: string;
  familyId: string;
  generation?: number;
  expiresAt: Date;
  userAgent?: string | null;
  ipAddress?: string | null;
}

export interface ISessionRepository {
  create(data: CreateSessionData): Promise<Session>;
  findByTokenHash(tokenHash: string): Promise<(Session & { user?: User }) | null>;
  findById(id: string): Promise<Session | null>;
  findActiveByUserId(userId: string): Promise<Session[]>;
  update(id: string, data: Partial<Omit<Session, 'id' | 'userId' | 'createdAt'>>): Promise<Session>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
  delete(id: string): Promise<void>;
}

export interface CreatePasswordResetData {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
}

export interface IPasswordResetRepository {
  create(data: CreatePasswordResetData): Promise<PasswordResetToken>;
  findByTokenHash(tokenHash: string): Promise<PasswordResetToken | null>;
  markAsUsed(id: string): Promise<void>;
}

export interface CreateOAuthAccountData {
  userId: string;
  provider: string;
  providerUserId: string;
}

export interface IOAuthAccountRepository {
  create(data: CreateOAuthAccountData): Promise<OAuthAccount>;
  findByProvider(provider: string, providerUserId: string): Promise<(OAuthAccount & { user?: User }) | null>;
  findByUserId(userId: string): Promise<OAuthAccount[]>;
}

export interface CreateAuditLogData {
  userId?: string | null;
  action: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: any;
}

export interface IAuditRepository {
  log(data: CreateAuditLogData): Promise<AuditEvent>;
  listByUser(userId: string, limit?: number): Promise<AuditEvent[]>;
}
