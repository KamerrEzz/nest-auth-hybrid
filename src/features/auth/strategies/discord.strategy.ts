import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-discord';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../../../modules/user/user.service';

@Injectable()
export class DiscordStrategy extends PassportStrategy(Strategy, 'discord') {
  constructor(
    private config: ConfigService,
    private users: UserService,
  ) {
    super({
      clientID: config.get<string>('app.discordClientId') ?? '',
      clientSecret: config.get<string>('app.discordClientSecret') ?? '',
      callbackURL:
        config.get<string>('app.discordCallbackUrl') ??
        '/auth/discord/callback',
      scope: ['identify', 'email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: unknown,
  ): Promise<{ id: string }> {
    const p = profile as { email?: string; username?: string };
    const email = p.email;
    if (!email) throw new Error('Discord profile missing email');
    let user = await this.users.findByEmail(email);
    if (!user) {
      user = await this.users.create({
        email,
        password: accessToken.slice(0, 10),
        name: p.username,
      });
    }
    return { id: user.id };
  }
}
