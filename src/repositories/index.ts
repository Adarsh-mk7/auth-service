import { config } from '../config/environment';
import {
  IUserRepository,
  ISessionRepository,
  IPasswordResetRepository,
  IOAuthAccountRepository,
  IAuditRepository,
} from './interfaces';
import { getPrismaClient } from './prisma/prismaClient';
import { PrismaUserRepository } from './prisma/PrismaUserRepository';
import { PrismaSessionRepository } from './prisma/PrismaSessionRepository';
import { PrismaPasswordResetRepository } from './prisma/PrismaPasswordResetRepository';
import { PrismaOAuthAccountRepository } from './prisma/PrismaOAuthAccountRepository';
import { PrismaAuditRepository } from './prisma/PrismaAuditRepository';
import { InMemoryUserRepository } from './in-memory/InMemoryUserRepository';
import { InMemorySessionRepository } from './in-memory/InMemorySessionRepository';
import { InMemoryPasswordResetRepository } from './in-memory/InMemoryPasswordResetRepository';
import { InMemoryOAuthAccountRepository } from './in-memory/InMemoryOAuthAccountRepository';
import { InMemoryAuditRepository } from './in-memory/InMemoryAuditRepository';

export * from './interfaces';

export interface RepositoryContainer {
  users: IUserRepository;
  sessions: ISessionRepository;
  passwordResets: IPasswordResetRepository;
  oauthAccounts: IOAuthAccountRepository;
  audits: IAuditRepository;
}

export const createInMemoryRepositories = (): RepositoryContainer => {
  const users = new InMemoryUserRepository();
  const sessions = new InMemorySessionRepository(users);
  const passwordResets = new InMemoryPasswordResetRepository();
  const oauthAccounts = new InMemoryOAuthAccountRepository(users);
  const audits = new InMemoryAuditRepository();

  return {
    users,
    sessions,
    passwordResets,
    oauthAccounts,
    audits,
  };
};

export const createPrismaRepositories = (): RepositoryContainer => {
  const prisma = getPrismaClient();
  return {
    users: new PrismaUserRepository(prisma),
    sessions: new PrismaSessionRepository(prisma),
    passwordResets: new PrismaPasswordResetRepository(prisma),
    oauthAccounts: new PrismaOAuthAccountRepository(prisma),
    audits: new PrismaAuditRepository(prisma),
  };
};

let defaultRepositories: RepositoryContainer | null = null;

export const getRepositories = (): RepositoryContainer => {
  if (!defaultRepositories) {
    if (config.NODE_ENV === 'test') {
      defaultRepositories = createInMemoryRepositories();
    } else {
      defaultRepositories = createPrismaRepositories();
    }
  }
  return defaultRepositories;
};

export const setRepositories = (repos: RepositoryContainer): void => {
  defaultRepositories = repos;
};
