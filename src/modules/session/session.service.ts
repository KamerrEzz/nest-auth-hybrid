import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import { SessionEntity } from './entities/session.entity';

@Injectable()
export class SessionService {
  private redis: Redis;
  constructor(private config: ConfigService) {
    this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
  }

  async create(
    userId: string,
    ttlMs: number,
    meta?: Partial<Omit<SessionEntity, 'id' | 'userId' | 'expiresAt'>>,
  ) {
    const id = randomUUID();
    const expiresAt = Date.now() + ttlMs;
    const session: SessionEntity = {
      id,
      userId,
      expiresAt,
      ipAddress: meta?.ipAddress,
      userAgent: meta?.userAgent,
    };
    await this.redis.setex(
      this.key(id),
      Math.floor(ttlMs / 1000),
      JSON.stringify(session),
    );
    return session;
  }

  async get(id: string) {
    const raw = await this.redis.get(this.key(id));
    return raw ? (JSON.parse(raw) as SessionEntity) : null;
  }

  async revoke(id: string) {
    await this.redis.del(this.key(id));
  }

  async listByUser(userId: string) {
    const items: SessionEntity[] = [];
    let cursor = '0';
    do {
      const res = await this.redis.scan(
        cursor,
        'MATCH',
        'session:*',
        'COUNT',
        100,
      );
      cursor = res[0];
      const keys = res[1];
      if (keys.length) {
        const vals = await this.redis.mget(...keys);
        for (const v of vals) {
          if (!v) continue;
          const s = JSON.parse(v) as SessionEntity;
          if (s.userId === userId) items.push(s);
        }
      }
    } while (cursor !== '0');
    return items;
  }

  private key(id: string) {
    return `session:${id}`;
  }
}
