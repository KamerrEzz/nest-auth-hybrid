import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SessionService } from '../../modules/session/session.service';
import { PrismaRepository } from '../../modules/database/prisma/prisma.service';
import type { Request } from 'express';

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(
    private sessions: SessionService,
    private prisma: PrismaRepository,
  ) {}

  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<Request>();
    const sid = req.cookies?.sessionId as string | undefined;
    if (!sid) throw new UnauthorizedException();
    const session = await this.sessions.get(sid);
    if (!session) throw new UnauthorizedException();
    const user = await this.prisma.findUserById(session.userId);
    if (!user) throw new UnauthorizedException();
    await this.sessions.touch(sid);
    req.user = { id: session.userId };
    return true;
  }
}
