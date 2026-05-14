import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

const prisma = new PrismaClient();

const BCRYPT_ROUNDS = 10;

async function main() {
  console.log('🌱 Seeding database...');

  // ── Clean existing seed data ─────────────────────────────────────────
  await prisma.oAuthToken.deleteMany();
  await prisma.oAuthAuthCode.deleteMany();
  await prisma.oAuthApp.deleteMany();
  await prisma.session.deleteMany();
  await prisma.auditLog.deleteMany();
  await prisma.user.deleteMany();
  console.log('  ✓ Cleared existing data');

  // ── Users ────────────────────────────────────────────────────────────
  const adminPassword = await bcrypt.hash('Admin1234!', BCRYPT_ROUNDS);
  const userPassword = await bcrypt.hash('User1234!', BCRYPT_ROUNDS);

  const admin = await prisma.user.create({
    data: {
      email: 'admin@vaultauth.dev',
      password: adminPassword,
      name: 'Admin VaultAuth',
      emailVerified: true,
    },
  });

  const user = await prisma.user.create({
    data: {
      email: 'user@vaultauth.dev',
      password: userPassword,
      name: 'Usuario Demo',
      emailVerified: true,
    },
  });

  console.log(`  ✓ Created users: ${admin.email}, ${user.email}`);

  // ── OAuth app for vaultauth-demo-app ─────────────────────────────────
  const plainSecret = randomBytes(32).toString('hex');
  const hashedSecret = await bcrypt.hash(plainSecret, BCRYPT_ROUNDS);

  const demoApp = await prisma.oAuthApp.create({
    data: {
      name: 'VaultAuth Demo App',
      description:
        'Aplicación de demostración que consume VaultAuth como proveedor OAuth',
      redirectUris: [
        'http://localhost:3002/api/auth/callback/vaultauth',
        'http://localhost:3002/callback',
      ],
      scopes: ['openid', 'profile', 'email'],
      userId: admin.id,
      clientSecret: hashedSecret,
    },
  });

  console.log('  ✓ Created OAuth app: VaultAuth Demo App');
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  📋 SEED CREDENTIALS — copy these to your .env.local');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  console.log('  👤 Test users:');
  console.log('     admin@vaultauth.dev  /  Admin1234!');
  console.log('     user@vaultauth.dev   /  User1234!');
  console.log('');
  console.log('  🔑 OAuth App (vaultauth-demo-app):');
  console.log(`     VAULTAUTH_CLIENT_ID=${demoApp.clientId}`);
  console.log(`     VAULTAUTH_CLIENT_SECRET=${plainSecret}`);
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
