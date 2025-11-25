import { registerAs } from '@nestjs/config';

export default registerAs('session', () => {
  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error(
      'SESSION_SECRET must be set and at least 32 characters long. ' +
      'Generate a secure secret with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }

  return {
    secret,
    maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
  };
});
