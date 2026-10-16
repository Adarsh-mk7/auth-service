import { Router } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from '../../services/auth.service';
import { SessionService } from '../../services/session.service';
import { PasswordService } from '../../services/password.service';
import { RepositoryContainer, getRepositories } from '../../repositories';
import { validate } from '../../middleware/validate';
import { authenticate } from '../../middleware/authenticate';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from '../../validators/auth.validator';

export const createAuthRouter = (repos?: RepositoryContainer): Router => {
  const router = Router();
  const repositoryContainer = repos || getRepositories();
  const authService = new AuthService(repositoryContainer);
  const sessionService = new SessionService(repositoryContainer);
  const passwordService = new PasswordService(repositoryContainer);
  const authController = new AuthController(authService, sessionService, passwordService);

  // POST /api/auth/register
  router.post('/register', validate(registerSchema), authController.register);

  // POST /api/auth/login
  router.post('/login', validate(loginSchema), authController.login);

  // POST /api/auth/refresh
  router.post('/refresh', authController.refresh);

  // POST /api/auth/logout
  router.post('/logout', authController.logout as any);

  // POST /api/auth/logout-all
  router.post('/logout-all', authenticate as any, authController.logoutAll as any);

  // GET /api/auth/sessions
  router.get('/sessions', authenticate as any, authController.getSessions as any);

  // GET /api/auth/me
  router.get('/me', authenticate as any, authController.getMe as any);

  // POST /api/auth/forgot-password
  router.post('/forgot-password', validate(forgotPasswordSchema), authController.forgotPassword);

  // POST /api/auth/reset-password
  router.post('/reset-password', validate(resetPasswordSchema), authController.resetPassword);

  // POST /api/auth/change-password
  router.post('/change-password', authenticate as any, validate(changePasswordSchema), authController.changePassword as any);

  return router;
};
