import { PasswordResetToken } from '@prisma/client';
import { IPasswordResetRepository, CreatePasswordResetData } from '../interfaces';
import crypto from 'crypto';

export class InMemoryPasswordResetRepository implements IPasswordResetRepository {
  private tokens: Map<string, PasswordResetToken> = new Map();

  async create(data: CreatePasswordResetData): Promise<PasswordResetToken> {
    const existing = await this.findByTokenHash(data.tokenHash);
    if (existing) {
      throw new Error(`Unique constraint failed on the fields: (tokenHash)`);
    }

    const resetToken: PasswordResetToken = {
      id: crypto.randomUUID(),
      userId: data.userId,
      tokenHash: data.tokenHash,
      expiresAt: data.expiresAt,
      usedAt: null,
      createdAt: new Date(),
    };

    this.tokens.set(resetToken.id, resetToken);
    return { ...resetToken };
  }

  async findByTokenHash(tokenHash: string): Promise<PasswordResetToken | null> {
    for (const token of this.tokens.values()) {
      if (token.tokenHash === tokenHash) {
        return { ...token };
      }
    }
    return null;
  }

  async markAsUsed(id: string): Promise<void> {
    const token = this.tokens.get(id);
    if (token) {
      this.tokens.set(id, { ...token, usedAt: new Date() });
    }
  }

  clear(): void {
    this.tokens.clear();
  }
}
