import { registerAs } from '@nestjs/config';

export default registerAs('session', () => ({
  secret: process.env.SESSION_SECRET ?? 'change-me-session',
  maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
}));
