import { Role } from '@prisma/client';

export type Permission =
  | 'auth:register'
  | 'auth:login'
  | 'auth:refresh'
  | 'auth:logout'
  | 'profile:read:own'
  | 'profile:update:own'
  | 'users:list:basic'
  | 'users:list:full'
  | 'admin:users:manage'
  | 'admin:roles:update'
  | 'audit:read:all';

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  USER: [
    'auth:register',
    'auth:login',
    'auth:refresh',
    'auth:logout',
    'profile:read:own',
    'profile:update:own',
    'users:list:basic',
  ],
  MODERATOR: [
    'auth:register',
    'auth:login',
    'auth:refresh',
    'auth:logout',
    'profile:read:own',
    'profile:update:own',
    'users:list:basic',
    'users:list:full',
  ],
  ADMIN: [
    'auth:register',
    'auth:login',
    'auth:refresh',
    'auth:logout',
    'profile:read:own',
    'profile:update:own',
    'users:list:basic',
    'users:list:full',
    'admin:users:manage',
    'admin:roles:update',
    'audit:read:all',
  ],
};

export const hasPermission = (role: Role, permission: Permission): boolean => {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
};
