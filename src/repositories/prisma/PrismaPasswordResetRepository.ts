import { PrismaClient, PasswordResetToken } from '@prisma/client';
import { IPasswordResetRepository, CreatePasswordResetData } from '../interfaces';

export class PrismaPasswordResetRepository implements IPasswordResetRepository {
  constructor(private prisma: PrismaClient) {}

  async create(data: CreatePasswordResetData): Promise<PasswordResetToken> {
    return this.prisma.passwordResetToken.create({
      data: {
        userId: data.userId,
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
      },
    });
  }

  async findByTokenHash(tokenHash: string): Promise<PasswordResetToken | null> {
    return this.prisma.passwordResetToken.findUnique({
      where: { tokenHash },
    });
  }

  async markAsUsed(id: string): Promise<void> {
    await this.prisma.passwordResetToken.update({
      where: { id },
      data: { usedAt: new Date() },
    });
  }
}
