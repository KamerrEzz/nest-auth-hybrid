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
import { randomUUID } from 'crypto';

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
      const csrfToken = randomUUID();
      res.cookie('csrfToken', csrfToken, {
        httpOnly: false,
        secure: isProd,
        sameSite: 'strict',
        maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
      });
      (result as any).csrfToken = csrfToken;
    }
    return result;
  }

  @Post('verify-otp')
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.verifyOtp(
      dto.tempToken,
      dto.otpCode,
      dto.totpCode,
    );
    const sid = (result as { sessionId?: string }).sessionId;
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', sid ?? '', {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'strict',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    (result as any).csrfToken = csrfToken;
    return result;
  }

  @Post('enable-2fa')
  @UseGuards(HybridAuthGuard)
  async enable2fa(@CurrentUser() user?: { id: string }) {
    if (!user) return { ok: false };
    return this.auth.enable2fa(user.id, user.id);
  }

  @Post('verify-2fa')
  @UseGuards(HybridAuthGuard)
  async verify2fa(
    @CurrentUser() user: { id: string },
    @Body() body: { code: string },
  ) {
    return this.auth.verify2fa(user.id, body.code);
  }

  @Post('disable-2fa')
  @UseGuards(HybridAuthGuard)
  async disable2fa(@CurrentUser() user: { id: string }) {
    await this.auth.disable2fa(user.id);
    return { ok: true };
  }

  @Get('csrf')
  csrf(@Res({ passthrough: true }) res: Response) {
    const isProd = process.env.NODE_ENV === 'production';
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'strict',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    return { csrfToken };
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
