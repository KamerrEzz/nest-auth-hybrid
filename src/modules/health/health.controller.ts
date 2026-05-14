import { Controller, Get, Inject } from '@nestjs/common';
import { PrismaRepository } from '../database/prisma/prisma.service';
import { REDIS_CLIENT } from '../redis/redis.constants';
import type Redis from 'ioredis';

@Controller('health')
export class HealthController {
  constructor(
    private prisma: PrismaRepository,
    @Inject(REDIS_CLIENT) private redis: Redis,
  ) {}

  @Get()
  async check() {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  @Get('detailed')
  async detailed() {
    const checks: Record<string, 'ok' | 'error'> = {};

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.database = 'ok';
    } catch {
      checks.database = 'error';
    }

    try {
      await this.redis.ping();
      checks.redis = 'ok';
    } catch {
      checks.redis = 'error';
    }

    const allOk = Object.values(checks).every((v) => v === 'ok');
    return {
      status: allOk ? 'ok' : 'degraded',
      checks,
      timestamp: new Date().toISOString(),
    };
  }
}
