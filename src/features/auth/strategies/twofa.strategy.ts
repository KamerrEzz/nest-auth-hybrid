import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as CustomStrategy } from 'passport-custom';
import type { Request } from 'express';
import { OtpService } from '../../../modules/otp/otp.service';
import { UserService } from '../../../modules/user/user.service';
import { TotpService } from '../../../modules/totp/totp.service';

@Injectable()
export class TwoFaStrategy extends PassportStrategy(CustomStrategy, 'twofa') {
  constructor(
    private otp: OtpService,
    private users: UserService,
    private totp: TotpService,
  ) {
    super();
  }

  async validate(req: Request): Promise<{ id: string }> {
    const body = (req.body ?? {}) as {
      tempToken?: string;
      otpCode?: string;
      totpCode?: string;
    };
    const tempToken = body.tempToken ?? '';
    const otpCode = body.otpCode ?? '';
    const totpCode = body.totpCode ?? '';
    const email = otpCode
      ? await this.otp.verify(tempToken, otpCode)
      : await this.otp.resolve(tempToken);
    if (!email) throw new UnauthorizedException();
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException();
    if (!user.totpSecret) throw new UnauthorizedException();
    const secret = this.totp.decryptSecret(user.totpSecret);
    const ok = this.totp.verify(totpCode, secret);
    if (!ok) throw new UnauthorizedException();
    return { id: user.id };
  }
}
