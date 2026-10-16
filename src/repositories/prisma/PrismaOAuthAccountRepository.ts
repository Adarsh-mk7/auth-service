import { PrismaClient, OAuthAccount, User } from '@prisma/client';
import { IOAuthAccountRepository, CreateOAuthAccountData } from '../interfaces';

export class PrismaOAuthAccountRepository implements IOAuthAccountRepository {
  constructor(private prisma: PrismaClient) {}

  async create(data: CreateOAuthAccountData): Promise<OAuthAccount> {
    return this.prisma.oAuthAccount.create({
      data: {
        userId: data.userId,
        provider: data.provider,
        providerUserId: data.providerUserId,
      },
    });
  }

  async findByProvider(provider: string, providerUserId: string): Promise<(OAuthAccount & { user?: User }) | null> {
    return this.prisma.oAuthAccount.findUnique({
      where: {
        provider_providerUserId: {
          provider,
          providerUserId,
        },
      },
      include: { user: true },
    });
  }

  async findByUserId(userId: string): Promise<OAuthAccount[]> {
    return this.prisma.oAuthAccount.findMany({
      where: { userId },
    });
  }
}
