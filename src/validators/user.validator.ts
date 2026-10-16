import { z } from 'zod';
import { Role } from '@prisma/client';

export const updateRoleSchema = z.object({
  role: z.nativeEnum(Role, {
    errorMap: () => ({ message: "Role must be one of: 'USER', 'MODERATOR', 'ADMIN'" }),
  }),
});

export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
