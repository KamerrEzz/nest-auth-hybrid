import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type Redis from 'ioredis';
import { REDIS_CLIENT } from '../../modules/redis/redis.constants';
import type { Request } from 'express';

interface RateLimitOptions {
  points: number;
  duration: number;
}

const RATE_LIMIT_LUA = `
  local key = KEYS[1]
  local limit = tonumber(ARGV[1])
  local ttl = tonumber(ARGV[2])

  local count = tonumber(redis.call('GET', key) or '0')
  if count and count >= limit then
    return -1
  end
  count = redis.call('INCR', key)
  if count == 1 then
    redis.call('EXPIRE', key, ttl)
  end
  return count
`;

@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(REDIS_CLIENT) private redis: Redis,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rateLimitOptions = this.reflector.get<RateLimitOptions>(
      'rateLimit',
      context.getHandler(),
    );

    if (!rateLimitOptions) return true;

    const req = context.switchToHttp().getRequest<Request>();
    const key = `rl:${req.ip}:${req.path}`;

    const result = await this.redis.eval(
      RATE_LIMIT_LUA,
      1,
      key,
      rateLimitOptions.points,
      rateLimitOptions.duration,
    );

    const count = result as number;
    if (count === -1) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Too many requests, please try again later',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }
}
