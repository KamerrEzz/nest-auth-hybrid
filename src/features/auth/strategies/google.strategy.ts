import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../../../modules/user/user.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private config: ConfigService,
    private users: UserService,
  ) {
    super({
      clientID: config.get<string>('app.googleClientId') ?? '',
      clientSecret: config.get<string>('app.googleClientSecret') ?? '',
      callbackURL:
        config.get<string>('app.googleCallbackUrl') ?? '/auth/google/callback',
      scope: ['profile', 'email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: unknown,
  ): Promise<{ id: string }> {
    const p = profile as {
      emails?: { value?: string }[];
      displayName?: string;
    };
    const email = p.emails?.[0]?.value;
    if (!email) throw new Error('Google profile missing email');
    let user = await this.users.findByEmail(email);
    if (!user) {
      user = await this.users.create({
        email,
        password: accessToken.slice(0, 10),
        name: p.displayName,
      });
    }
    return { id: user.id };
  }
}
