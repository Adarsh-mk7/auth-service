import { OAuthAccount, User } from '@prisma/client';
import { IOAuthAccountRepository, CreateOAuthAccountData, IUserRepository } from '../interfaces';
import crypto from 'crypto';

export class InMemoryOAuthAccountRepository implements IOAuthAccountRepository {
  private accounts: Map<string, OAuthAccount> = new Map();
  private userRepo?: IUserRepository;

  constructor(userRepo?: IUserRepository) {
    this.userRepo = userRepo;
  }

  setUserRepository(userRepo: IUserRepository) {
    this.userRepo = userRepo;
  }

  async create(data: CreateOAuthAccountData): Promise<OAuthAccount> {
    const existing = await this.findByProvider(data.provider, data.providerUserId);
    if (existing) {
      throw new Error(`Unique constraint failed on the fields: (provider, providerUserId)`);
    }

    const now = new Date();
    const account: OAuthAccount = {
      id: crypto.randomUUID(),
      userId: data.userId,
      provider: data.provider,
      providerUserId: data.providerUserId,
      createdAt: now,
      updatedAt: now,
    };

    this.accounts.set(account.id, account);
    return { ...account };
  }

  async findByProvider(provider: string, providerUserId: string): Promise<(OAuthAccount & { user?: User }) | null> {
    for (const account of this.accounts.values()) {
      if (account.provider === provider && account.providerUserId === providerUserId) {
        let user: User | undefined;
        if (this.userRepo) {
          const found = await this.userRepo.findById(account.userId);
          if (found) user = found;
        }
        return { ...account, user };
      }
    }
    return null;
  }

  async findByUserId(userId: string): Promise<OAuthAccount[]> {
    const result: OAuthAccount[] = [];
    for (const account of this.accounts.values()) {
      if (account.userId === userId) {
        result.push({ ...account });
      }
    }
    return result;
  }

  clear(): void {
    this.accounts.clear();
  }
}
