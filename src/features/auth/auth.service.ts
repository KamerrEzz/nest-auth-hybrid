import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../../modules/user/user.service';
import { TokenService } from '../../modules/token/token.service';
import { SessionService } from '../../modules/session/session.service';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { OtpService } from '../../modules/otp/otp.service';
import { EmailService } from '../../modules/email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private users: UserService,
    private tokens: TokenService,
    private sessions: SessionService,
    private config: ConfigService,
    private otp: OtpService,
    private email: EmailService,
  ) {}

  async register(email: string, password: string, name?: string) {
    const exists = await this.users.findByEmail(email);
    if (exists) throw new UnauthorizedException();
    return this.users.create({ email, password, name });
  }

  async login(email: string, password: string) {
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) throw new UnauthorizedException();
    if (user.has2FA) {
      const rec = await this.otp.generate(user.email);
      await this.email.sendOtp(user.email, rec.code);
      return { requiresOtp: true, tempToken: rec.tempToken };
    }
    const accessToken = await this.tokens.signAccess({ sub: user.id });
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      {},
    );
    return { accessToken, refreshToken, sessionId: session.id };
  }

  async verifyOtp(tempToken: string, otpCode: string) {
    const email = await this.otp.verify(tempToken, otpCode);
    if (!email) throw new UnauthorizedException();
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    const accessToken = await this.tokens.signAccess({ sub: user.id });
    const refreshToken = await this.tokens.signRefresh({ sub: user.id });
    const session = await this.sessions.create(
      user.id,
      this.config.get<number>('session.maxAge')!,
      {},
    );
    return { accessToken, refreshToken, sessionId: session.id };
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
}
