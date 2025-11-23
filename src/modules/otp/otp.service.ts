import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';

@Injectable()
export class OtpService {
  private redis: Redis;
  constructor(private config: ConfigService) {
    this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
  }

  async generate(email: string) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const tempToken = randomUUID();
    const ttlMs = 10 * 60 * 1000;
    const record = { tempToken, email, code, expiresAt: Date.now() + ttlMs };
    await this.redis.setex(
      this.key(tempToken),
      Math.floor(ttlMs / 1000),
      JSON.stringify(record),
    );
    return record;
  }

  async generateTicket(email: string) {
    const tempToken = randomUUID();
    const ttlMs = 10 * 60 * 1000;
    const record = { tempToken, email, expiresAt: Date.now() + ttlMs };
    await this.redis.setex(
      this.key(tempToken),
      Math.floor(ttlMs / 1000),
      JSON.stringify(record),
    );
    return record;
  }

  async verify(tempToken: string, code: string) {
    const raw = await this.redis.get(this.key(tempToken));
    if (!raw) return null;
    const rec = JSON.parse(raw) as { code?: string; email: string };
    const ok = rec.code === code;
    if (!ok) return null;
    await this.redis.del(this.key(tempToken));
    return rec.email;
  }

  async resolve(tempToken: string) {
    const raw = await this.redis.get(this.key(tempToken));
    if (!raw) return null;
    const rec = JSON.parse(raw) as { email: string };
    await this.redis.del(this.key(tempToken));
    return rec.email;
  }

  private key(token: string) {
    return `otp:${token}`;
  }
}
