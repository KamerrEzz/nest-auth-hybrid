import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class TokenService {
  constructor(
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  signAccess(payload: Record<string, any>) {
    return this.jwt.signAsync(payload, {
      secret: this.config.get<string>('jwt.secret')!,
      expiresIn: this.parseDuration(
        this.config.get<string>('jwt.accessExpiration'),
      ),
    });
  }

  signRefresh(payload: Record<string, any>) {
    return this.jwt.signAsync(payload, {
      secret: this.config.get<string>('jwt.refreshSecret')!,
      expiresIn: this.parseDuration(
        this.config.get<string>('jwt.refreshExpiration'),
      ),
    });
  }

  verifyAccess(token: string) {
    return this.jwt.verifyAsync(token, {
      secret: this.config.get<string>('jwt.secret')!,
    });
  }

  verifyRefresh(token: string) {
    return this.jwt.verifyAsync(token, {
      secret: this.config.get<string>('jwt.refreshSecret')!,
    });
  }

  private parseDuration(value: string | number | undefined) {
    if (typeof value === 'number') return value;
    if (!value) return undefined;
    const s = String(value);
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    const m = s.match(/^(\d+)([smhd])$/);
    if (!m) return undefined as unknown as number;
    const num = parseInt(m[1], 10);
    const unit = m[2];
    const map = { s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>;
    return num * map[unit];
  }
}
