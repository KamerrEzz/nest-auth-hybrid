import { Body, Controller, Get, Post, Res, UseGuards } from '@nestjs/common';
import { Delete, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { UserService } from '../../modules/user/user.service';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly users: UserService,
  ) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto.email, dto.password, dto.name);
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.login(dto.email, dto.password);
    const sid = (result as { sessionId?: string }).sessionId;
    if (sid) {
      const isProd = process.env.NODE_ENV === 'production';
      res.cookie('sessionId', sid, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
      });
    }
    return result;
  }

  @Post('verify-otp')
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.verifyOtp(dto.tempToken, dto.otpCode);
    const sid = (result as { sessionId?: string }).sessionId;
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', sid ?? '', {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    return result;
  }

  @Post('refresh')
  refresh(@Body() dto: RefreshTokenDto) {
    return this.auth.refresh(dto.refreshToken);
  }

  @Get('me')
  @UseGuards(HybridAuthGuard)
  async me(@CurrentUser() user?: { id: string }) {
    if (!user) return null;
    return this.users.findById(user.id);
  }

  @Post('logout')
  @UseGuards(HybridAuthGuard)
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('sessionId');
    return { ok: true };
  }

  @Get('sessions')
  @UseGuards(HybridAuthGuard)
  async sessions(@CurrentUser() user?: { id: string }) {
    if (!user) return [];
    return this.auth.listSessions(user.id);
  }

  @Delete('sessions/:id')
  @UseGuards(HybridAuthGuard)
  async revoke(@Param('id') id: string) {
    await this.auth.revokeSession(id);
    return { ok: true };
  }
}
