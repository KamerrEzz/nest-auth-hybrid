import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../../modules/user/user.service';
import { TokenService } from '../../modules/token/token.service';
import { SessionService } from '../../modules/session/session.service';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { OtpService } from '../../modules/otp/otp.service';
import { EmailService } from '../../modules/email/email.service';
import { TotpService } from '../../modules/totp/totp.service';
import type { UserEntity } from '../../common/types/auth.types';

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
  ) {}

  async register(
    email: string,
    password: string,
    name?: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<RegisterResult> {
    const exists = await this.users.findByEmail(email);
    if (exists) throw new UnauthorizedException();
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
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
    return { user, accessToken, refreshToken, sessionId: session.id };
  }

  async login(
    email: string,
    password: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess | RequiresOtp> {
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) throw new UnauthorizedException();
    if (user.has2FA) {
      const rec = await this.otp.generate(user.email);
      await this.email.sendOtp(user.email, rec.code);
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
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
    return { accessToken, refreshToken, sessionId: session.id, user };
  }

  async verifyOtp(
    tempToken: string,
    otpCode: string,
    totpCode?: string,
    meta?: { ipAddress?: string; userAgent?: string; location?: string },
  ): Promise<LoginSuccess> {
    const email = await this.otp.verify(tempToken, otpCode);
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
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
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
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
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
    const rawBackups = Array.from({ length: 10 }, () =>
      Math.random().toString(36).slice(2, 10),
    );
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const hashed = await Promise.all(
      rawBackups.map((code) => bcrypt.hash(code, rounds)),
    );
    await this.users.enable2FA(userId, enc, hashed);
    const qr = await this.totp.generateQrDataUrl(s.otpauthUrl);
    return { qrCode: qr, secret: s.base32, backupCodes: rawBackups };
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
    await this.users.confirm2FA(userId);
    return { ok: true };
  }

  async refresh(refreshToken: string) {
    const payload = (await this.tokens.verifyRefresh(refreshToken)) as {
      sub: string;
    };
    const accessToken = await this.tokens.signAccess({ sub: payload.sub });
    return { accessToken };
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
}
