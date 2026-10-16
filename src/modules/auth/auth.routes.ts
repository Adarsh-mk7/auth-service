import { Router } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from '../../services/auth.service';
import { SessionService } from '../../services/session.service';
import { PasswordService } from '../../services/password.service';
import { RepositoryContainer, getRepositories } from '../../repositories';
import { validate } from '../../middleware/validate';
import { authenticate } from '../../middleware/authenticate';
import { createRateLimiter } from '../../middleware/rateLimiter';
import { createOAuthRouter } from '../oauth/oauth.routes';
import { config } from '../../config/environment';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from '../../validators/auth.validator';

export interface AuthRouteOptions {
  repos?: RepositoryContainer;
  rateLimits?: {
    loginMax?: number;
    registerMax?: number;
    forgotPasswordMax?: number;
    refreshMax?: number;
  };
}

export const createAuthRouter = (options?: AuthRouteOptions): Router => {
  const router = Router();
  const repositoryContainer = options?.repos || getRepositories();
  const authService = new AuthService(repositoryContainer);
  const sessionService = new SessionService(repositoryContainer);
  const passwordService = new PasswordService(repositoryContainer);
  const authController = new AuthController(authService, sessionService, passwordService);

  const isTest = config.NODE_ENV === 'test';
  const loginMax = options?.rateLimits?.loginMax ?? (isTest ? 500 : config.RATE_LIMIT_AUTH_MAX_REQUESTS);
  const registerMax = options?.rateLimits?.registerMax ?? (isTest ? 500 : 10);
  const forgotPwMax = options?.rateLimits?.forgotPasswordMax ?? (isTest ? 500 : 5);
  const refreshMax = options?.rateLimits?.refreshMax ?? (isTest ? 500 : 50);

  // Rate Limiters for sensitive authentication endpoints
  const loginLimiter = createRateLimiter({
    prefix: 'login',
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: loginMax,
    message: 'Too many login attempts. Please try again later.',
  });

  const registerLimiter = createRateLimiter({
    prefix: 'register',
    windowMs: 60 * 60 * 1000,
    max: registerMax,
    message: 'Too many registration requests from this IP. Please try again later.',
  });

  const forgotPasswordLimiter = createRateLimiter({
    prefix: 'forgot-pw',
    windowMs: 60 * 60 * 1000,
    max: forgotPwMax,
    message: 'Too many password reset attempts. Please try again later.',
  });

  const refreshLimiter = createRateLimiter({
    prefix: 'refresh',
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: refreshMax,
  });

  // POST /api/auth/register
  router.post('/register', registerLimiter, validate(registerSchema), authController.register);

  // POST /api/auth/login
  router.post('/login', loginLimiter, validate(loginSchema), authController.login);

  // POST /api/auth/refresh
  router.post('/refresh', refreshLimiter, authController.refresh);

  // POST /api/auth/logout
  router.post('/logout', authController.logout as any);

  // POST /api/auth/logout-all
  router.post('/logout-all', authenticate as any, authController.logoutAll as any);

  // GET /api/auth/sessions
  router.get('/sessions', authenticate as any, authController.getSessions as any);

  // GET /api/auth/me
  router.get('/me', authenticate as any, authController.getMe as any);

  // POST /api/auth/forgot-password
  router.post('/forgot-password', forgotPasswordLimiter, validate(forgotPasswordSchema), authController.forgotPassword);

  // POST /api/auth/reset-password
  router.post('/reset-password', validate(resetPasswordSchema), authController.resetPassword);

  // POST /api/auth/change-password
  router.post('/change-password', authenticate as any, validate(changePasswordSchema), authController.changePassword as any);

  // Mount OAuth routes: /api/auth/google and /api/auth/google/callback
  router.use('/', createOAuthRouter(repositoryContainer));

  return router;
};
