import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { parseDuration } from '../../common/utils/parse-duration';

@Injectable()
export class TokenService {
  constructor(
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  signAccess(payload: Record<string, any>) {
    return this.jwt.signAsync(payload, {
      secret: this.config.get<string>('jwt.secret')!,
      expiresIn: parseDuration(this.config.get<string>('jwt.accessExpiration')) || 3600,
    });
  }

  signRefresh(payload: Record<string, any>) {
    return this.jwt.signAsync(payload, {
      secret: this.config.get<string>('jwt.refreshSecret')!,
      expiresIn: parseDuration(this.config.get<string>('jwt.refreshExpiration')) || 604800,
    });
  }

  verifyAccess(token: string) {
    return this.jwt.verifyAsync(token, {
      secret: this.config.get<string>('jwt.secret')!,
      algorithms: ['HS256'],
    });
  }

  verifyRefresh(token: string) {
    return this.jwt.verifyAsync(token, {
      secret: this.config.get<string>('jwt.refreshSecret')!,
      algorithms: ['HS256'],
    });
  }

}
