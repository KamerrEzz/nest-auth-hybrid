import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../../modules/user/user.module';
import { TokenModule } from '../../modules/token/token.module';
import { SessionModule } from '../../modules/session/session.module';
import { OtpModule } from '../../modules/otp/otp.module';
import { EmailModule } from '../../modules/email/email.module';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { SessionAuthGuard } from '../../common/guards/session-auth.guard';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';

@Module({
  imports: [UserModule, TokenModule, SessionModule, OtpModule, EmailModule],
  controllers: [AuthController],
  providers: [AuthService, JwtAuthGuard, SessionAuthGuard, HybridAuthGuard],
})
export class AuthModule {}
