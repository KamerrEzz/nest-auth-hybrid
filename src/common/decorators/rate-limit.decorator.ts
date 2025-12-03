import { SetMetadata } from '@nestjs/common';

export const RATE_LIMIT_KEY = 'rateLimit';

/**
 * Decorator to apply rate limiting to a route
 * @param points - Number of allowed requests
 * @param duration - Time window in seconds
 */
export const RateLimit = (points: number, duration: number) =>
  SetMetadata(RATE_LIMIT_KEY, { points, duration });
