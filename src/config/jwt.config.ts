import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET ?? 'change-me',
  refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'change-me-refresh',
  accessExpiration: process.env.JWT_ACCESS_EXPIRATION ?? '15m',
  refreshExpiration: process.env.JWT_REFRESH_EXPIRATION ?? '7d',
}));
