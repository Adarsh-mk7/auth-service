import { PrismaClient, Role } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  if (process.env.NODE_ENV === 'production') {
    console.error('ERROR: Seed script cannot be run in production mode to avoid insecure defaults.');
    process.exit(1);
  }

  console.log('[Seed] Seeding development database...');

  // Clean existing development records safely
  await prisma.auditEvent.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.session.deleteMany();
  await prisma.oauthAccount.deleteMany();
  await prisma.user.deleteMany();

  const devPassword = process.env.DEV_SEED_PASSWORD || 'DevPassword123!';
  const passwordHash = await bcrypt.hash(devPassword, 10);

  const admin = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      name: 'System Admin',
      passwordHash,
      role: Role.ADMIN,
      isEmailVerified: true,
    },
  });

  const moderator = await prisma.user.create({
    data: {
      email: 'moderator@example.com',
      name: 'Community Moderator',
      passwordHash,
      role: Role.MODERATOR,
      isEmailVerified: true,
    },
  });

  const regularUser = await prisma.user.create({
    data: {
      email: 'user@example.com',
      name: 'Standard User',
      passwordHash,
      role: Role.USER,
      isEmailVerified: true,
    },
  });

  console.log('[Seed] Seed completed successfully:');
  console.log(`- Admin User: ${admin.email}`);
  console.log(`- Moderator User: ${moderator.email}`);
  console.log(`- Standard User: ${regularUser.email}`);
  console.log(`- Development Password: ${devPassword}`);
}

main()
  .catch((e) => {
    console.error('[Seed] Error during seeding:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
