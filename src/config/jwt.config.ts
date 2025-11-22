import { registerAs } from '@nestjs/config';

function fallback(value: string | undefined, def: string) {
  return value && value.length > 0 ? value : def;
}

export default registerAs('jwt', () => ({
  secret: fallback(process.env.JWT_SECRET, 'change-me'),
  refreshSecret: fallback(process.env.JWT_REFRESH_SECRET, 'change-me-refresh'),
  accessExpiration: fallback(process.env.JWT_ACCESS_EXPIRATION, '15m'),
  refreshExpiration: fallback(process.env.JWT_REFRESH_EXPIRATION, '7d'),
}));
