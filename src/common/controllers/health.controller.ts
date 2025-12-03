import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { PrismaRepository } from '../../modules/database/prisma/prisma.service';

@Controller('health')
export class HealthController {
  private redis: Redis;

  constructor(
    private config: ConfigService,
    private prisma: PrismaRepository,
  ) {
    this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
  }

  @Get()
  async check() {
    const checks = await Promise.allSettled([
      this.checkRedis(),
      this.checkDatabase(),
    ]);

    const isHealthy = checks.every((c) => c.status === 'fulfilled');

    return {
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      checks: {
        redis: checks[0].status === 'fulfilled' ? 'up' : 'down',
        database: checks[1].status === 'fulfilled' ? 'up' : 'down',
      },
    };
  }

  private async checkRedis() {
    await this.redis.ping();
  }

  private async checkDatabase() {
    await this.prisma.$queryRaw`SELECT 1`;
  }
}
