import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
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
import { randomUUID, randomBytes } from 'crypto';
import { Inject } from '@nestjs/common';
import type Redis from 'ioredis';
import { REDIS_CLIENT } from '../../modules/redis/redis.constants';
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
  constructor(
    private users: UserService,
    private tokens: TokenService,
    private sessions: SessionService,
    private config: ConfigService,
    private otp: OtpService,
    private email: EmailService,
    private totp: TotpService,
    private audit: AuditLogService,
    @Inject(REDIS_CLIENT) private redis: Redis,
  ) {}

  private readonly LOCKOUT_THRESHOLD = 5;
  private readonly LOCKOUT_TTL_S = 15 * 60;

  private lockoutKey(email: string) {
    return `lockout:${email.toLowerCase()}`;
  }

  private async isLocked(email: string): Promise<boolean> {
    const val = await this.redis.get(this.lockoutKey(email));
    return parseInt(val ?? '0', 10) >= this.LOCKOUT_THRESHOLD;
  }

  private async incrementLockout(email: string): Promise<void> {
    const key = this.lockoutKey(email);
    const count = await this.redis.incr(key);
    if (count === 1) await this.redis.expire(key, this.LOCKOUT_TTL_S);
  }

  private async clearLockout(email: string): Promise<void> {
    await this.redis.del(this.lockoutKey(email));
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
    // Send verification email (non-blocking)
    this.sendVerificationEmail(user.id).catch(() => undefined);
    return { user, accessToken, refreshToken, sessionId: session.id };
  }

  async login(
    email: string,
    password: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess | RequiresOtp> {
    if (await this.isLocked(email)) {
      throw new UnauthorizedException(
        'Account temporarily locked. Try again later.',
      );
    }
    const user = await this.users.findByEmail(email);
    if (!user) {
      await this.incrementLockout(email);
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
      await this.incrementLockout(email);
      await this.audit.logFailedLogin(
        email,
        'invalid_password',
        meta?.ipAddress,
        meta?.userAgent,
      );
      throw new UnauthorizedException();
    }
    await this.clearLockout(email);
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

  async enable2fa(userId: string, label: string, currentTotpCode?: string) {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    if (user.has2FA && user.totpSecret) {
      const existingSecret = this.totp.decryptSecret(user.totpSecret);
      const valid = currentTotpCode
        ? this.totp.verify(currentTotpCode, existingSecret)
        : false;
      if (!valid)
        throw new UnauthorizedException(
          'Current TOTP required to regenerate 2FA',
        );
    }
    const s = this.totp.generateSecret(label);
    const enc = this.totp.encryptSecret(s.base32);
    await this.users.enable2FA(userId, enc);
    const qr = await this.totp.generateQrDataUrl(s.otpauthUrl);
    return { qrCode: qr };
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
    if (!authorized) {
      if (!user.has2FA) {
        await this.users.cancel2FA(userId);
        return { ok: true };
      }
      throw new UnauthorizedException();
    }
    await this.users.disable2FA(userId);
    await this.audit.log2FADisabled(userId);
    return { ok: true };
  }

  async verify2fa(userId: string, code: string) {
    const user = await this.users.findById(userId);
    if (!user || !user.totpSecret) throw new UnauthorizedException();
    const secret = this.totp.decryptSecret(user.totpSecret);
    const ok = this.totp.verify(code, secret);
    if (!ok) throw new UnauthorizedException();
    const rawBackups = Array.from({ length: 10 }, () =>
      randomBytes(5).toString('hex'),
    );
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const hashed = await Promise.all(
      rawBackups.map((x) => bcrypt.hash(x, rounds)),
    );
    await this.users.confirm2FA(userId, hashed);
    await this.audit.log2FAEnabled(userId);
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

    if (payload.jti) {
      const isRevoked = await this.redis.get(`revoked:${payload.jti}`);
      if (isRevoked) throw new UnauthorizedException('Token has been revoked');
    }

    const user = await this.users.findById(payload.sub);
    if (!user) throw new UnauthorizedException();

    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      meta ?? {},
    );

    const newAccessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
    });

    const newJti = randomUUID();
    const newRefreshToken = await this.tokens.signRefresh({
      sub: user.id,
      jti: newJti,
    });

    if (payload.jti) {
      const ttl = 7 * 24 * 60 * 60;
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

  async revokeSession(id: string, ownerUserId: string) {
    const session = await this.sessions.get(id);
    if (!session) throw new NotFoundException();
    if (session.userId !== ownerUserId) throw new ForbiddenException();
    await this.sessions.revoke(id);
  }

  async revokeAllSessions(userId: string) {
    await this.sessions.revokeAllByUser(userId);
  }

  async revokeOtherSessions(userId: string, keepId: string) {
    await this.sessions.revokeAllByUserExcept(userId, keepId);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.users.findByEmail(email);
    // Always return ok — never reveal if email exists (prevent enumeration)
    if (!user) return;
    const token = randomBytes(32).toString('hex');
    // TTL: 1 hour
    await this.redis.setex(`reset:${token}`, 3600, user.id);
    const frontendUrl =
      this.config.get<string>('app.frontendUrl') ?? 'http://localhost:3001';
    const resetUrl = `${frontendUrl}/reset-password/${token}`;
    await this.email.sendPasswordReset(user.email, resetUrl);
  }

  async resetPassword(
    token: string,
    newPassword: string,
    meta?: { ipAddress?: string; userAgent?: string },
  ): Promise<void> {
    const userId = await this.redis.get(`reset:${token}`);
    if (!userId) throw new UnauthorizedException('Token inválido o expirado');
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const hash = await bcrypt.hash(newPassword, rounds);
    await this.users.updatePassword(userId, hash);
    // Invalidate the token immediately after use
    await this.redis.del(`reset:${token}`);
    // Revoke all sessions for security
    await this.sessions.revokeAllByUser(userId);
    await this.audit.logPasswordChange(
      userId,
      meta?.ipAddress,
      meta?.userAgent,
    );
  }

  async sendVerificationEmail(userId: string): Promise<void> {
    const user = await this.users.findById(userId);
    if (!user || user.emailVerified) return;
    const token = randomBytes(32).toString('hex');
    // TTL: 24 hours
    await this.redis.setex(`verify:${token}`, 86400, userId);
    const frontendUrl =
      this.config.get<string>('app.frontendUrl') ?? 'http://localhost:3001';
    const verificationUrl = `${frontendUrl}/verify-email?token=${token}`;
    await this.email.sendEmailVerification(user.email, verificationUrl);
  }

  async verifyEmail(token: string): Promise<void> {
    const userId = await this.redis.get(`verify:${token}`);
    if (!userId) throw new UnauthorizedException('Token inválido o expirado');
    await this.users.verifyEmail(userId);
    await this.redis.del(`verify:${token}`);
  }
}
