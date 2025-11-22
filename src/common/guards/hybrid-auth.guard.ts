import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { SessionAuthGuard } from './session-auth.guard';

@Injectable()
export class HybridAuthGuard implements CanActivate {
  constructor(
    private jwt: JwtAuthGuard,
    private session: SessionAuthGuard,
  ) {}

  async canActivate(ctx: ExecutionContext) {
    try {
      if (await this.jwt.canActivate(ctx)) return true;
    } catch {
      // fall back to session
    }
    return this.session.canActivate(ctx);
  }
}
