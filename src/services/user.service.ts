import { RepositoryContainer } from '../repositories';
import { Role, User } from '@prisma/client';
import { NotFoundError, BadRequestError } from '../utils/errors';
import { sanitizeUser, UserResponseDto } from './auth.service';

export interface BasicUserDto {
  id: string;
  name: string;
}

export class UserService {
  constructor(private repos: RepositoryContainer) {}

  async listUsers(
    requesterRole: Role,
    skip = 0,
    take = 20
  ): Promise<{ users: (UserResponseDto | BasicUserDto)[]; total: number }> {
    const { users, total } = await this.repos.users.list(skip, take);

    if (requesterRole === Role.USER) {
      // Regular users only see basic public directory info (privacy preservation)
      return {
        users: users.map((u: User) => ({
          id: u.id,
          name: u.name,
        })),
        total,
      };
    }

    // MODERATOR and ADMIN can view full profile details
    return {
      users: users.map(sanitizeUser),
      total,
    };
  }

  async adminListUsers(
    skip = 0,
    take = 20
  ): Promise<{ users: UserResponseDto[]; total: number }> {
    const { users, total } = await this.repos.users.list(skip, take);
    return {
      users: users.map(sanitizeUser),
      total,
    };
  }

  async updateUserRole(
    adminUserId: string,
    targetUserId: string,
    newRole: Role,
    ipAddress?: string,
    userAgent?: string
  ): Promise<UserResponseDto> {
    const targetUser = await this.repos.users.findById(targetUserId);
    if (!targetUser) {
      throw new NotFoundError('Target user not found');
    }

    // Protection against admin self-demotion lockout
    if (adminUserId === targetUserId && targetUser.role === Role.ADMIN && newRole !== Role.ADMIN) {
      const { users } = await this.repos.users.list(0, 100);
      const adminCount = users.filter((u: User) => u.role === Role.ADMIN).length;

      if (adminCount <= 1) {
        throw new BadRequestError('Cannot demote the sole remaining system administrator');
      }
    }

    const previousRole = targetUser.role;
    const updatedUser = await this.repos.users.update(targetUserId, { role: newRole });

    await this.repos.audits.log({
      userId: adminUserId,
      action: 'ROLE_UPDATED',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: {
        targetUserId,
        previousRole,
        newRole,
      },
    });

    return sanitizeUser(updatedUser);
  }

  async getUserById(userId: string): Promise<UserResponseDto> {
    const user = await this.repos.users.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    return sanitizeUser(user);
  }
}
