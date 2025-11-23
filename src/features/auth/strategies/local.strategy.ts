import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { UserService } from '../../../modules/user/user.service';
import * as bcrypt from 'bcrypt';
import { OtpService } from '../../../modules/otp/otp.service';

export type LocalResult =
  | { requiresOtp: true; tempToken: string }
  | { id: string };

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
  constructor(
    private users: UserService,
    private otp: OtpService,
  ) {
    super({ usernameField: 'email', passwordField: 'password' });
  }

  async validate(email: string, password: string): Promise<LocalResult> {
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) throw new UnauthorizedException();
    if (user.has2FA) {
      const rec = await this.otp.generateTicket(user.email);
      return { requiresOtp: true, tempToken: rec.tempToken };
    }
    return { id: user.id };
  }
}
