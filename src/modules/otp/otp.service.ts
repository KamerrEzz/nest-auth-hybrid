import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import type Redis from 'ioredis';
import { REDIS_CLIENT } from '../redis/redis.constants';
import { randomUUID, randomBytes } from 'crypto';

@Injectable()
export class OtpService {
  constructor(@Inject(REDIS_CLIENT) private redis: Redis) {}

  async generate(email: string) {
    const code = (100000 + (randomBytes(4).readUInt32BE(0) % 900000)).toString();
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

    const rec = JSON.parse(raw) as {
      code?: string;
      email: string;
      attempts?: number;
      expiresAt: number;
    };

    if (rec.expiresAt < Date.now()) {
      await this.redis.del(this.key(tempToken));
      return null;
    }

    const attempts = (rec.attempts || 0) + 1;

    if (attempts > 3) {
      await this.redis.del(this.key(tempToken));
      throw new UnauthorizedException('Too many failed attempts');
    }

    const ok = rec.code === code;

    if (!ok) {
      rec.attempts = attempts;
      const ttl = Math.max(1, Math.floor((rec.expiresAt - Date.now()) / 1000));
      await this.redis.setex(this.key(tempToken), ttl, JSON.stringify(rec));
      return null;
    }

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
