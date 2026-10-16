import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types';
import { TokenUtil } from '../utils/token';
import { UnauthorizedError } from '../utils/errors';

export const authenticate = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new UnauthorizedError('Authentication required: Bearer token missing');
  }

  const token = authHeader.substring(7).trim();
  if (!token) {
    throw new UnauthorizedError('Authentication token missing');
  }

  try {
    const decoded = TokenUtil.verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    next(error);
  }
};
