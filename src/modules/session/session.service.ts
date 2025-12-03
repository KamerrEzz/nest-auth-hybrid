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

    const ttlSec = Math.floor(ttlMs / 1000);

    // Guardar sesión
    await this.redis.setex(this.key(id), ttlSec, JSON.stringify(session));

    // Indexar por usuario usando SET de Redis
    await this.redis.sadd(this.userSessionsKey(userId), id);
    await this.redis.expire(this.userSessionsKey(userId), ttlSec);

    return session;
  }

  async get(id: string) {
    const raw = await this.redis.get(this.key(id));
    if (!raw) return null;

    const session = JSON.parse(raw) as SessionEntity;

    // Validar expiración explícitamente (además del TTL de Redis)
    if (session.expiresAt < Date.now()) {
      await this.redis.del(this.key(id));
      return null;
    }

    return session;
  }

  async revoke(id: string) {
    const session = await this.get(id);
    if (session) {
      await this.redis.srem(this.userSessionsKey(session.userId), id);
    }
    await this.redis.del(this.key(id));
  }

  async revokeAllByUser(userId: string) {
    const sessionIds = await this.redis.smembers(this.userSessionsKey(userId));

    if (sessionIds.length === 0) return;

    // Usar pipeline para eliminar en batch
    const pipeline = this.redis.pipeline();
    sessionIds.forEach((id) => pipeline.del(this.key(id)));
    pipeline.del(this.userSessionsKey(userId));
    await pipeline.exec();
  }

  async revokeAllByUserExcept(userId: string, keepId: string) {
    const sessionIds = await this.redis.smembers(this.userSessionsKey(userId));

    if (sessionIds.length === 0) return;

    // Filtrar sesiones excepto la que queremos mantener
    const toDelete = sessionIds.filter((id) => id !== keepId);

    if (toDelete.length === 0) return;

    // Usar pipeline para eliminar en batch
    const pipeline = this.redis.pipeline();
    toDelete.forEach((id) => {
      pipeline.del(this.key(id));
      pipeline.srem(this.userSessionsKey(userId), id);
    });
    await pipeline.exec();
  }

  async listByUser(userId: string) {
    const sessionIds = await this.redis.smembers(this.userSessionsKey(userId));

    if (sessionIds.length === 0) return [];

    const sessions = await this.redis.mget(
      ...sessionIds.map((id) => this.key(id)),
    );

    return sessions
      .filter((s) => s !== null)
      .map((s) => JSON.parse(s) as SessionEntity);
  }

  private key(id: string) {
    return `session:${id}`;
  }

  private userSessionsKey(userId: string) {
    return `user:${userId}:sessions`;
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
