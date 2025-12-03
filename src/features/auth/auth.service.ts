import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { UserService } from '../../modules/user/user.service';
import { TokenService } from '../../modules/token/token.service';
import { SessionService } from '../../modules/session/session.service';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { OtpService } from '../../modules/otp/otp.service';
import { EmailService } from '../../modules/email/email.service';
import { TotpService } from '../../modules/totp/totp.service';
import type { UserEntity } from '../../common/types/auth.types';
import { randomUUID } from 'crypto';
import Redis from 'ioredis';
import { AuditLogService } from '../../modules/audit/audit-log.service';

export interface RegisterResult {
  user: UserEntity;
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}

export interface LoginSuccess {
  user: UserEntity;
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}

export interface RequiresOtp {
  requiresOtp: true;
  tempToken: string;
}

@Injectable()
export class AuthService {
  private redis: Redis;

  constructor(
    private users: UserService,
    private tokens: TokenService,
    private sessions: SessionService,
    private config: ConfigService,
    private otp: OtpService,
    private email: EmailService,
    private totp: TotpService,
    private audit: AuditLogService,
  ) {
    this.redis = new Redis(this.config.get<string>('cache.redisUrl')!);
  }

  async register(
    email: string,
    password: string,
    name?: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<RegisterResult> {
    const exists = await this.users.findByEmail(email);
    if (exists) throw new ConflictException('Email ya registrado');
    const user = await this.users.create({ email, password, name });
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });
    const jti = randomUUID();
    const refreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti,
    });
    return { user, accessToken, refreshToken, sessionId: session.id };
  }

  async login(
    email: string,
    password: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess | RequiresOtp> {
    const user = await this.users.findByEmail(email);
    if (!user) {
      await this.audit.logFailedLogin(
        email,
        'user_not_found',
        meta?.ipAddress,
        meta?.userAgent,
      );
      throw new UnauthorizedException();
    }
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      await this.audit.logFailedLogin(
        email,
        'invalid_password',
        meta?.ipAddress,
        meta?.userAgent,
      );
      throw new UnauthorizedException();
    }
    if (user.has2FA) {
      const rec = await this.otp.generateTicket(user.email);
      return { requiresOtp: true, tempToken: rec.tempToken };
    }
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });
    const jti = randomUUID();
    const refreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti,
    });
    await this.audit.logSuccessfulLogin(
      user.id,
      meta?.ipAddress,
      meta?.userAgent,
    );
    return { accessToken, refreshToken, sessionId: session.id, user };
  }

  async verifyOtp(
    tempToken: string,
    otpCode?: string,
    totpCode?: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess> {
    const email = otpCode
      ? await this.otp.verify(tempToken, otpCode)
      : await this.otp.resolve(tempToken);
    if (!email) throw new UnauthorizedException();
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    if (user.has2FA && user.totpSecret) {
      const secret = this.totp.decryptSecret(user.totpSecret);
      const ok = totpCode ? this.totp.verify(totpCode, secret) : false;
      if (!ok) throw new UnauthorizedException();
    }
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });
    const jti = randomUUID();
    const refreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti,
    });
    return { accessToken, refreshToken, sessionId: session.id, user };
  }

  async issueForUserId(
    userId: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });
    const jti = randomUUID();
    const refreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti,
    });
    return { accessToken, refreshToken, sessionId: session.id, user };
  }

  async begin2faForUserId(userId: string): Promise<RequiresOtp> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const rec = await this.otp.generate(user.email);
    await this.email.sendOtp(user.email, rec.code);
    return { requiresOtp: true, tempToken: rec.tempToken };
  }

  async enable2fa(userId: string, label: string) {
    const s = this.totp.generateSecret(label);
    const enc = this.totp.encryptSecret(s.base32);
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    await this.users.enable2FA(userId, enc);
    const qr = await this.totp.generateQrDataUrl(s.otpauthUrl);
    return { qrCode: qr, secret: s.base32 };
  }

  async disable2fa(
    userId: string,
    body?: { totpCode?: string; backupCode?: string },
  ) {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const byTotp = body?.totpCode ?? '';
    const byBackup = body?.backupCode ?? '';
    let authorized = false;
    if (byTotp && user.totpSecret) {
      const secret = this.totp.decryptSecret(user.totpSecret);
      authorized = this.totp.verify(byTotp, secret);
    }
    if (!authorized && byBackup) {
      authorized = await this.users.consumeBackupCode(userId, byBackup);
    }
    // Permitir cancelar si aún no está confirmado (has2FA=false)
    if (!authorized) {
      if (!user.has2FA) {
        await this.users.cancel2FA(userId);
        return { ok: true };
      }
      throw new UnauthorizedException();
    }
    await this.users.disable2FA(userId);
    return { ok: true };
  }

  async verify2fa(userId: string, code: string) {
    const user = await this.users.findById(userId);
    if (!user || !user.totpSecret) throw new UnauthorizedException();
    const secret = this.totp.decryptSecret(user.totpSecret);
    const ok = this.totp.verify(code, secret);
    if (!ok) throw new UnauthorizedException();
    const rawBackups = Array.from({ length: 10 }, () =>
      Math.random().toString(36).slice(2, 10),
    );
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const hashed = await Promise.all(
      rawBackups.map((x) => bcrypt.hash(x, rounds)),
    );
    await this.users.confirm2FA(userId, hashed);
    return { ok: true, backupCodes: rawBackups };
  }

  async changePassword(
    userId: string,
    body: { currentPassword: string; newPassword: string; totpCode?: string },
    meta?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const okCurrent = await bcrypt.compare(body.currentPassword, user.password);
    if (!okCurrent) throw new UnauthorizedException();
    if (user.has2FA && user.totpSecret) {
      const secret = this.totp.decryptSecret(user.totpSecret);
      const okTotp = body.totpCode
        ? this.totp.verify(body.totpCode, secret)
        : false;
      if (!okTotp) throw new UnauthorizedException();
    }
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const newHash = await bcrypt.hash(body.newPassword, rounds);
    await this.users.updatePassword(userId, newHash);
    await this.audit.logPasswordChange(
      userId,
      meta?.ipAddress,
      meta?.userAgent,
    );
    return { ok: true };
  }

  async refresh(
    refreshToken: string,
    meta?: { ipAddress?: string; userAgent?: string },
  ) {
    const payload = (await this.tokens.verifyRefresh(refreshToken)) as {
      sub: string;
      jti?: string;
    };

    // Validar que el token no haya sido revocado
    if (payload.jti) {
      const isRevoked = await this.redis.get(`revoked:${payload.jti}`);
      if (isRevoked) {
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    const user = await this.users.findById(payload.sub);
    if (!user) throw new UnauthorizedException();

    // Crear nueva sesión
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );

    // Generar NUEVOS tokens
    const newAccessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });

    const newJti = randomUUID();
    const newRefreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti: newJti,
    });

    // Revocar el refresh token anterior
    if (payload.jti) {
      const ttl = 7 * 24 * 60 * 60; // 7 días
      await this.redis.setex(`revoked:${payload.jti}`, ttl, '1');
    }

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async listSessions(userId: string) {
    return this.sessions.listByUser(userId);
  }

  async revokeSession(id: string) {
    await this.sessions.revoke(id);
  }

  async revokeAllSessions(userId: string) {
    await this.sessions.revokeAllByUser(userId);
  }

  async revokeOtherSessions(userId: string, keepId: string) {
    await this.sessions.revokeAllByUserExcept(userId, keepId);
  }
}
