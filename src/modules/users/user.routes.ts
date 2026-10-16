import { Router } from 'express';
import { UserController } from './user.controller';
import { UserService } from '../../services/user.service';
import { RepositoryContainer, getRepositories } from '../../repositories';
import { authenticate } from '../../middleware/authenticate';
import { authorizeRoles, requireOwnershipOrRole } from '../../middleware/authorize';
import { validate } from '../../middleware/validate';
import { updateRoleSchema } from '../../validators/user.validator';
import { Role } from '@prisma/client';

export const createUserRouter = (repos?: RepositoryContainer): Router => {
  const router = Router();
  const repositoryContainer = repos || getRepositories();
  const userService = new UserService(repositoryContainer);
  const userController = new UserController(userService);

  // GET /api/users (authenticated users, returns basic or full info based on role)
  router.get('/', authenticate as any, userController.listUsers as any);

  // GET /api/users/:id (protected by resource ownership or admin/moderator override)
  router.get(
    '/:id',
    authenticate as any,
    requireOwnershipOrRole('id', [Role.ADMIN, Role.MODERATOR]) as any,
    userController.getUserById as any
  );

  return router;
};

export const createAdminRouter = (repos?: RepositoryContainer): Router => {
  const router = Router();
  const repositoryContainer = repos || getRepositories();
  const userService = new UserService(repositoryContainer);
  const userController = new UserController(userService);

  // Restrict all routes under /api/admin to ADMIN role
  router.use(authenticate as any);
  router.use(authorizeRoles(Role.ADMIN) as any);

  // GET /api/admin/users
  router.get('/users', userController.adminListUsers as any);

  // PATCH /api/admin/users/:id/role
  router.patch('/users/:id/role', validate(updateRoleSchema), userController.updateRole as any);

  return router;
};
