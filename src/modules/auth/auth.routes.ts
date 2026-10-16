import { Router } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from '../../services/auth.service';
import { RepositoryContainer, getRepositories } from '../../repositories';
import { validate } from '../../middleware/validate';
import { registerSchema } from '../../validators/auth.validator';

export const createAuthRouter = (repos?: RepositoryContainer): Router => {
  const router = Router();
  const repositoryContainer = repos || getRepositories();
  const authService = new AuthService(repositoryContainer);
  const authController = new AuthController(authService);

  // POST /api/auth/register
  router.post('/register', validate(registerSchema), authController.register);

  return router;
};
