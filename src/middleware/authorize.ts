import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types';
import { Role } from '@prisma/client';
import { ForbiddenError, UnauthorizedError } from '../utils/errors';

/**
 * Middleware enforcing Role-Based Access Control (RBAC).
 * Rejects requests with 403 Forbidden if user's role is not in the allowed list.
 */
export const authorizeRoles = (...allowedRoles: Role[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new ForbiddenError(`Forbidden: Access denied. Required role: ${allowedRoles.join(' or ')}`)
      );
    }

    next();
  };
};

/**
 * Middleware enforcing Resource Ownership or Role override.
 * Ensures users can only access their own resource unless they hold an overriding role (e.g., ADMIN).
 */
export const requireOwnershipOrRole = (
  resourceIdParam = 'id',
  overrideRoles: Role[] = [Role.ADMIN]
) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    const targetResourceId = req.params[resourceIdParam];
    const isOwner = req.user.id === targetResourceId;
    const hasOverrideRole = overrideRoles.includes(req.user.role);

    if (!isOwner && !hasOverrideRole) {
      return next(
        new ForbiddenError('Forbidden: You do not have permission to access or modify this resource')
      );
    }

    next();
  };
};
