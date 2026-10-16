import { Request } from 'express';

export type UserRole = 'USER' | 'MODERATOR' | 'ADMIN';

export interface UserContext {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  isEmailVerified: boolean;
}

export interface AuthenticatedRequest extends Request {
  user?: UserContext;
  sessionId?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: any;
}
