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
      location: meta?.location,
      expiresAt,
      ipAddress: meta?.ipAddress,
      userAgent: meta?.userAgent,
      lastActive: Date.now(),
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

  async revokeAllByUser(userId: string) {
    let cursor = '0';
    const toDelete: string[] = [];
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
        for (let i = 0; i < vals.length; i++) {
          const v = vals[i];
          if (!v) continue;
          const s = JSON.parse(v) as SessionEntity;
          if (s.userId === userId) toDelete.push(keys[i]);
        }
      }
    } while (cursor !== '0');
    if (toDelete.length) await this.redis.del(...toDelete);
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

  async touch(id: string) {
    const raw = await this.redis.get(this.key(id));
    if (!raw) return;
    const s = JSON.parse(raw) as SessionEntity;
    const ttlSec = Math.max(1, Math.floor((s.expiresAt - Date.now()) / 1000));
    s.lastActive = Date.now();
    await this.redis.setex(this.key(id), ttlSec, JSON.stringify(s));
  }
}
