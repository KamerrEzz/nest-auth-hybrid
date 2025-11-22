import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';

@Injectable()
export class CsrfGuard implements CanActivate {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<Request>();
    const method = req.method.toUpperCase();
    if (method === 'GET') return true;
    if (method === 'HEAD' || method === 'OPTIONS') return true;
    const header = req.headers['x-csrf-token'] as string | undefined;
    const cookie = (req.cookies?.csrfToken ?? '') as string;
    if (!header || !cookie || header !== cookie) throw new ForbiddenException();
    return true;
  }
}
