import { User, Role } from '@prisma/client';
import { IUserRepository, CreateUserData } from '../interfaces';
import crypto from 'crypto';

export class InMemoryUserRepository implements IUserRepository {
  private users: Map<string, User> = new Map();

  async create(data: CreateUserData): Promise<User> {
    const existing = await this.findByEmail(data.email);
    if (existing) {
      throw new Error(`Unique constraint failed on the fields: (email)`);
    }

    const now = new Date();
    const user: User = {
      id: crypto.randomUUID(),
      email: data.email.toLowerCase(),
      name: data.name,
      passwordHash: data.passwordHash || null,
      role: data.role || Role.USER,
      isEmailVerified: data.isEmailVerified ?? false,
      createdAt: now,
      updatedAt: now,
    };

    this.users.set(user.id, user);
    return { ...user };
  }

  async findById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const normalized = email.toLowerCase();
    for (const user of this.users.values()) {
      if (user.email.toLowerCase() === normalized) {
        return { ...user };
      }
    }
    return null;
  }

  async update(id: string, data: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User> {
    const user = this.users.get(id);
    if (!user) {
      throw new Error(`User with id ${id} not found`);
    }

    const updatedUser: User = {
      ...user,
      ...data,
      updatedAt: new Date(),
    };
    this.users.set(id, updatedUser);
    return { ...updatedUser };
  }

  async list(skip = 0, take = 20): Promise<{ users: User[]; total: number }> {
    const all = Array.from(this.users.values()).sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime()
    );
    const paginated = all.slice(skip, skip + take);
    return {
      users: paginated.map((u) => ({ ...u })),
      total: all.length,
    };
  }

  async delete(id: string): Promise<void> {
    this.users.delete(id);
  }

  async count(): Promise<number> {
    return this.users.size;
  }

  clear(): void {
    this.users.clear();
  }
}
