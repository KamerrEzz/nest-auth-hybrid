import { registerAs } from '@nestjs/config';

export default registerAs('security', () => {
  const totpEncKey = process.env.TOTP_ENC_KEY;

  if (!totpEncKey) {
    throw new Error(
      'TOTP_ENC_KEY must be set. ' +
      'Generate a secure 256-bit key with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }

  // Validate key format (must be 64 hex chars or at least 32 chars)
  if (!/^[0-9a-fA-F]{64}$/.test(totpEncKey) && totpEncKey.length < 32) {
    throw new Error(
      'TOTP_ENC_KEY must be either a 64-character hex string or at least 32 characters long',
    );
  }

  return {
    rateLimitTtl: parseInt(process.env.RATE_LIMIT_TTL ?? '900000', 10),
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX ?? '100', 10),
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10),
    totpEncKey,
  };
});
