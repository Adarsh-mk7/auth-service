import { Response, NextFunction } from 'express';
import { UserService } from '../../services/user.service';
import { AuthenticatedRequest } from '../../types';
import { UnauthorizedError } from '../../utils/errors';
import { Role } from '@prisma/client';

export class UserController {
  constructor(private userService: UserService) {}

  listUsers = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const page = parseInt(req.query.page as string, 10) || 1;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const skip = (page - 1) * limit;

      const result = await this.userService.listUsers(req.user.role, skip, limit);

      res.status(200).json({
        success: true,
        message: 'Users retrieved successfully',
        data: {
          users: result.users,
          pagination: {
            page,
            limit,
            total: result.total,
            totalPages: Math.ceil(result.total / limit),
          },
        },
      });
    } catch (error) {
      next(error);
    }
  };

  adminListUsers = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string, 10) || 1;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const skip = (page - 1) * limit;

      const result = await this.userService.adminListUsers(skip, limit);

      res.status(200).json({
        success: true,
        message: 'Administrative user list retrieved',
        data: {
          users: result.users,
          pagination: {
            page,
            limit,
            total: result.total,
            totalPages: Math.ceil(result.total / limit),
          },
        },
      });
    } catch (error) {
      next(error);
    }
  };

  updateRole = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const targetUserId = req.params.id;
      const newRole: Role = req.body.role;
      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      const user = await this.userService.updateUserRole(
        req.user.id,
        targetUserId,
        newRole,
        ipAddress,
        userAgent
      );

      res.status(200).json({
        success: true,
        message: `User role successfully updated to ${newRole}`,
        data: { user },
      });
    } catch (error) {
      next(error);
    }
  };

  getUserById = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const targetUserId = req.params.id;
      const user = await this.userService.getUserById(targetUserId);

      res.status(200).json({
        success: true,
        message: 'User retrieved successfully',
        data: { user },
      });
    } catch (error) {
      next(error);
    }
  };
}
