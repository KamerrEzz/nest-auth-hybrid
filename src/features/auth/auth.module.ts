import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../../modules/user/user.module';
import { TokenModule } from '../../modules/token/token.module';
import { SessionModule } from '../../modules/session/session.module';
import { OtpModule } from '../../modules/otp/otp.module';
import { EmailModule } from '../../modules/email/email.module';
import { TotpModule } from '../../modules/totp/totp.module';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { TwoFaStrategy } from './strategies/twofa.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { DiscordStrategy } from './strategies/discord.strategy';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { SessionAuthGuard } from '../../common/guards/session-auth.guard';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    UserModule,
    TokenModule,
    SessionModule,
    OtpModule,
    EmailModule,
    TotpModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    JwtStrategy,
    TwoFaStrategy,
    GoogleStrategy,
    DiscordStrategy,
    JwtAuthGuard,
    SessionAuthGuard,
    HybridAuthGuard,
  ],
})
export class AuthModule {}
