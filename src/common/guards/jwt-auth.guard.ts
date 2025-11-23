import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { TokenService } from '../../modules/token/token.service';
import { SessionService } from '../../modules/session/session.service';
import type { Request } from 'express';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private tokens: TokenService,
    private sessions: SessionService,
  ) {}

  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<Request>();
    const auth = req.headers['authorization'];
    if (!auth || !auth.startsWith('Bearer ')) throw new UnauthorizedException();
    const token = auth.slice(7);
    try {
      const payload = (await this.tokens.verifyAccess(token)) as {
        sub: string;
        sid?: string;
      };
      if (!payload.sid) throw new UnauthorizedException();
      const s = await this.sessions.get(payload.sid);
      if (!s) throw new UnauthorizedException();
      await this.sessions.touch(payload.sid);
      req.user = { id: payload.sub };
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
