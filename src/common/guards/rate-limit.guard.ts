import {
    Injectable,
    CanActivate,
    ExecutionContext,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { Request } from 'express';

interface RateLimitOptions {
    points: number;
    duration: number;
}

@Injectable()
export class RateLimitGuard implements CanActivate {
    private redis: Redis;

    constructor(
        private reflector: Reflector,
        private config: ConfigService,
    ) {
        this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const rateLimitOptions = this.reflector.get<RateLimitOptions>(
            'rateLimit',
            context.getHandler(),
        );

        if (!rateLimitOptions) return true;

        const req = context.switchToHttp().getRequest<Request>();
        const key = `rl:${req.ip}:${req.path}`;

        const current = await this.redis.get(key);
        const count = current ? parseInt(current, 10) : 0;

        if (count >= rateLimitOptions.points) {
            throw new HttpException(
                {
                    statusCode: HttpStatus.TOO_MANY_REQUESTS,
                    message: 'Too many requests, please try again later',
                },
                HttpStatus.TOO_MANY_REQUESTS,
            );
        }

        // Incrementar contador
        const pipeline = this.redis.pipeline();
        pipeline.incr(key);
        if (count === 0) {
            pipeline.expire(key, rateLimitOptions.duration);
        }
        await pipeline.exec();

        return true;
    }
}
