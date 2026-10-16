import { RepositoryContainer } from '../repositories';
import { RegisterInput } from '../validators/auth.validator';
import { PasswordUtil } from '../utils/password';
import { ConflictError } from '../utils/errors';
import { User, Role } from '@prisma/client';

export interface UserResponseDto {
  id: string;
  email: string;
  name: string;
  role: Role;
  isEmailVerified: boolean;
  createdAt: Date;
}

export const sanitizeUser = (user: User): UserResponseDto => {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    createdAt: user.createdAt,
  };
};

export class AuthService {
  constructor(private repos: RepositoryContainer) {}

  async register(
    input: RegisterInput,
    ipAddress?: string,
    userAgent?: string
  ): Promise<UserResponseDto> {
    const normalizedEmail = input.email.trim().toLowerCase();

    // Check for existing user
    const existing = await this.repos.users.findByEmail(normalizedEmail);
    if (existing) {
      throw new ConflictError('An account with this email address already exists');
    }

    // Hash password
    const passwordHash = await PasswordUtil.hash(input.password);

    // Create user
    const user = await this.repos.users.create({
      email: normalizedEmail,
      name: input.name.trim(),
      passwordHash,
      role: Role.USER,
      isEmailVerified: false,
    });

    // Audit log
    await this.repos.audits.log({
      userId: user.id,
      action: 'USER_REGISTER',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: { email: user.email },
    });

    return sanitizeUser(user);
  }
}
