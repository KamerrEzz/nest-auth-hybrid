import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import { NoteEntity } from './entities/note.entity';

@Injectable()
export class NoteService {
  private redis: Redis;
  constructor(private config: ConfigService) {
    this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
  }

  async create(
    userId: string,
    data: { title: string; content: string; secure?: boolean },
  ) {
    const id = randomUUID();
    const now = Date.now();
    const note: NoteEntity = {
      id,
      userId,
      title: data.title,
      content: data.content,
      secure: !!data.secure,
      createdAt: now,
      updatedAt: now,
    };
    await this.redis.set(this.key(id), JSON.stringify(note));
    return note;
  }

  async get(id: string) {
    const raw = await this.redis.get(this.key(id));
    return raw ? (JSON.parse(raw) as NoteEntity) : null;
  }

  async listByUser(userId: string) {
    const items: NoteEntity[] = [];
    let cursor = '0';
    do {
      const res = await this.redis.scan(
        cursor,
        'MATCH',
        'note:*',
        'COUNT',
        100,
      );
      cursor = res[0];
      const keys = res[1];
      if (keys.length) {
        const vals = await this.redis.mget(...keys);
        for (const v of vals) {
          if (!v) continue;
          const n = JSON.parse(v) as NoteEntity;
          if (n.userId === userId) items.push(n);
        }
      }
    } while (cursor !== '0');
    return items;
  }

  async update(
    id: string,
    patch: Partial<Omit<NoteEntity, 'id' | 'userId' | 'createdAt'>>,
  ) {
    const raw = await this.redis.get(this.key(id));
    if (!raw) return null;
    const note = JSON.parse(raw) as NoteEntity;
    const next: NoteEntity = { ...note, ...patch, updatedAt: Date.now() };
    await this.redis.set(this.key(id), JSON.stringify(next));
    return next;
  }

  async delete(id: string) {
    await this.redis.del(this.key(id));
  }

  private key(id: string) {
    return `note:${id}`;
  }
}
