import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  port: parseInt(process.env.PORT ?? '3000', 10),
  url: process.env.APP_URL ?? 'http://localhost:3000',
}));
