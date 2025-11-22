import { registerAs } from '@nestjs/config';

export default registerAs('security', () => ({
  rateLimitTtl: parseInt(process.env.RATE_LIMIT_TTL ?? '900000', 10),
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX ?? '100', 10),
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10),
  totpEncKey:
    process.env.TOTP_ENC_KEY ??
    '4b6e701fe143659a6187a343b9d3ab503bc3e7918837d35df23fb86c343ab848',
}));
