import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Res,
  UseGuards,
  Req,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { Delete, Param } from '@nestjs/common';
import {
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiCookieAuth,
  ApiTags,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
// import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthGuard } from '@nestjs/passport';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';
import { CsrfGuard } from '../../common/guards/csrf.guard';
import { RateLimitGuard } from '../../common/guards/rate-limit.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RateLimit } from '../../common/decorators/rate-limit.decorator';
import { UserService } from '../../modules/user/user.service';
import type { Response } from 'express';
import { randomUUID } from 'crypto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { UserResponseDto } from '../../modules/user/dto/user-response.dto';
import { ConfigService } from '@nestjs/config';
import { instanceToPlain } from 'class-transformer';
import { parseDuration } from '../../common/utils/parse-duration';
import type { Request as ExpressRequest } from 'express';
import type { SessionEntity } from '../../modules/session/entities/session.entity';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly users: UserService,
    private readonly config: ConfigService,
  ) {}

  private toUserDto(entity: {
    id: string;
    email: string;
    name?: string | null;
    createdAt?: Date;
    emailVerified?: boolean;
  }) {
    return new UserResponseDto({
      id: entity.id,
      email: entity.email,
      name: entity.name ?? undefined,
      createdAt: entity.createdAt ?? new Date(),
      emailVerified: entity.emailVerified ?? false,
    });
  }

  @Post('register')
  @HttpCode(201)
  @RateLimit(5, 300)
  @UseGuards(RateLimitGuard)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'Registration successful' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: ExpressRequest,
  ): Promise<RegisterResponseDto> {
    const result = await this.auth.register(dto.email, dto.password, dto.name, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', result.sessionId, {
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
    const dtoOut = new RegisterResponseDto({
      message: 'Registration successful',
      user: this.toUserDto(result.user),
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
    return instanceToPlain(dtoOut) as RegisterResponseDto;
  }

  @Post('login')
  @RateLimit(5, 60)
  @UseGuards(RateLimitGuard, AuthGuard('local'))
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: ExpressRequest,
  ): Promise<AuthResponseDto | { requiresOtp: true; tempToken: string }> {
    const result = await this.auth.login(dto.email, dto.password, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    if ('requiresOtp' in result) {
      return { requiresOtp: true, tempToken: result.tempToken };
    }
    const sid = result.sessionId;
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
    const expiresIn = parseDuration(
      this.config.get<string>('jwt.accessExpiration'),
    );
    const dtoOut = new AuthResponseDto({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: this.toUserDto(result.user),
      expiresIn,
    });
    return instanceToPlain(dtoOut) as AuthResponseDto;
  }

  @Post('verify-otp')
  @RateLimit(3, 60)
  @UseGuards(RateLimitGuard, AuthGuard('twofa'))
  @ApiOperation({ summary: 'Verify 2FA OTP code' })
  @ApiResponse({ status: 200, description: 'OTP verification successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verifyOtp(
    @CurrentUser() user: { id: string },
    @Res({ passthrough: true }) res: Response,
    @Req() req: ExpressRequest,
  ): Promise<AuthResponseDto> {
    const result = await this.auth.issueForUserId(user.id, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', result.sessionId ?? '', {
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
    const expiresIn = parseDuration(
      this.config.get<string>('jwt.accessExpiration'),
    );
    const dtoOut = new AuthResponseDto({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: this.toUserDto(result.user),
      expiresIn,
    });
    return instanceToPlain(dtoOut) as AuthResponseDto;
  }

  @Post('enable-2fa')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Enable 2FA for the current user' })
  @ApiResponse({ status: 200, description: '2FA enabled successfully' })
  @ApiBearerAuth('JWT')
  async enable2fa(
    @CurrentUser() user?: { id: string },
    @Body() body?: { currentTotpCode?: string },
  ) {
    if (!user) return { ok: false };
    return this.auth.enable2fa(user.id, user.id, body?.currentTotpCode);
  }

  @Post('verify-2fa')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Verify 2FA code to confirm setup' })
  @ApiResponse({ status: 200, description: '2FA verified successfully' })
  @ApiBearerAuth('JWT')
  async verify2fa(
    @CurrentUser() user: { id: string },
    @Body() body: { code: string },
  ) {
    return this.auth.verify2fa(user.id, body.code);
  }

  @Get('2fa/status')
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'Get 2FA status for the current user' })
  @ApiResponse({ status: 200, description: '2FA status retrieved' })
  @ApiBearerAuth('JWT')
  async twofaStatus(@CurrentUser() user?: { id: string }) {
    if (!user) return { enabled: false };
    const entity = await this.users.findById(user.id);
    return {
      enabled: !!entity?.has2FA,
      hasSecret: !!entity?.totpSecret,
      backupCount: entity?.backupCodes?.length ?? 0,
    };
  }

  @Post('disable-2fa')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Disable 2FA for the current user' })
  @ApiResponse({ status: 200, description: '2FA disabled successfully' })
  @ApiBearerAuth('JWT')
  async disable2fa(
    @CurrentUser() user: { id: string },
    @Body() body: { totpCode?: string; backupCode?: string },
  ) {
    return this.auth.disable2fa(user.id, body);
  }

  @Post('2fa/cancel')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Cancel 2FA setup' })
  @ApiResponse({ status: 200, description: '2FA setup cancelled' })
  @ApiBearerAuth('JWT')
  async cancel2fa(@CurrentUser() user: { id: string }) {
    // Cancelar solo si no está confirmado aún
    return this.auth.disable2fa(user.id, {});
  }

  @Get('csrf')
  @ApiOperation({ summary: 'Get CSRF token' })
  @ApiResponse({ status: 200, description: 'CSRF token retrieved' })
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

  @Post('change-password')
  @RateLimit(5, 300)
  @UseGuards(RateLimitGuard, HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Change the current user password' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiBearerAuth('JWT')
  async changePassword(
    @CurrentUser() user: { id: string },
    @Body() dto: ChangePasswordDto,
    @Req() req: ExpressRequest,
  ) {
    return this.auth.changePassword(user.id, dto, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
  }

  @Post('refresh')
  @RateLimit(10, 60)
  @UseGuards(RateLimitGuard)
  @ApiOperation({ summary: 'Refresh an access token using a refresh token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async refresh(@Body() dto: RefreshTokenDto, @Req() req: ExpressRequest) {
    return this.auth.refresh(dto.refreshToken, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
  }

  @Get('me')
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved' })
  @ApiBearerAuth('JWT')
  async me(@CurrentUser() user?: { id: string }) {
    if (!user) return null;
    const entity = await this.users.findById(user.id);
    return entity
      ? (instanceToPlain(this.toUserDto(entity)) as UserResponseDto)
      : null;
  }

  @Post('logout')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Logout the current user' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  @ApiBearerAuth('JWT')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('sessionId');
    return { ok: true };
  }

  @Get('sessions')
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'List all active sessions' })
  @ApiResponse({ status: 200, description: 'Sessions listed' })
  @ApiBearerAuth('JWT')
  async sessions(
    @CurrentUser() user?: { id: string },
    @Req() req?: ExpressRequest,
  ): Promise<{ currentId: string; items: SessionEntity[] }> {
    const items = user ? await this.auth.listSessions(user.id) : [];
    const rawSid: unknown = req?.cookies?.sessionId;
    const currentId = typeof rawSid === 'string' ? rawSid : '';
    return { currentId, items };
  }

  @Delete('sessions')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Revoke all sessions for the current user' })
  @ApiResponse({ status: 200, description: 'All sessions revoked' })
  @ApiBearerAuth('JWT')
  async revokeAll(@CurrentUser() user?: { id: string }) {
    if (!user) return { ok: false };
    await this.auth.revokeAllSessions(user.id);
    return { ok: true };
  }

  @Delete('sessions/others')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Revoke all sessions except the current one' })
  @ApiResponse({ status: 200, description: 'Other sessions revoked' })
  @ApiBearerAuth('JWT')
  async revokeOthers(
    @CurrentUser() user: { id: string },
    @Req() req: ExpressRequest,
  ) {
    const rawSid: unknown = req.cookies?.sessionId;
    const currentId = typeof rawSid === 'string' ? rawSid : '';
    await this.auth.revokeOtherSessions(user.id, currentId);
    return { ok: true };
  }

  @Delete('sessions/:id')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  @ApiOperation({ summary: 'Revoke a specific session' })
  @ApiResponse({ status: 200, description: 'Session revoked' })
  @ApiBearerAuth('JWT')
  async revoke(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    await this.auth.revokeSession(id, user.id);
    return { ok: true };
  }

  @Post('forgot-password')
  @HttpCode(200)
  @RateLimit(3, 300)
  @UseGuards(RateLimitGuard)
  @ApiOperation({ summary: 'Request a password reset email' })
  @ApiResponse({ status: 200, description: 'Password reset email sent' })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.auth.forgotPassword(dto.email);
    return { ok: true };
  }

  @Post('reset-password')
  @HttpCode(200)
  @RateLimit(3, 300)
  @UseGuards(RateLimitGuard)
  @ApiOperation({ summary: 'Reset password using the reset token' })
  @ApiResponse({ status: 200, description: 'Password reset successful' })
  async resetPassword(
    @Body() dto: ResetPasswordDto,
    @Req() req: ExpressRequest,
  ) {
    await this.auth.resetPassword(dto.token, dto.newPassword, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    return { ok: true };
  }

  @Post('send-verification')
  @RateLimit(3, 300)
  @UseGuards(RateLimitGuard, HybridAuthGuard)
  @ApiOperation({ summary: 'Send a verification email' })
  @ApiResponse({ status: 200, description: 'Verification email sent' })
  @ApiBearerAuth('JWT')
  async sendVerification(@CurrentUser() user: { id: string }) {
    await this.auth.sendVerificationEmail(user.id);
    return { ok: true };
  }

  @Get('verify-email')
  @HttpCode(200)
  @RateLimit(10, 60)
  @UseGuards(RateLimitGuard)
  @ApiOperation({ summary: 'Verify email with a token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  async verifyEmail(@Query('token') token: string) {
    if (!token) throw new UnauthorizedException('Token requerido');
    await this.auth.verifyEmail(token);
    return { ok: true };
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Initiate Google OAuth2 login' })
  @ApiResponse({ status: 302, description: 'Redirect to Google OAuth' })
  google() {
    return;
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Google OAuth2 callback' })
  @ApiResponse({ status: 200, description: 'Google login successful' })
  async googleCallback(
    @CurrentUser() user: { id: string },
    @Res({ passthrough: true }) res: Response,
    @Req() req: ExpressRequest,
  ): Promise<AuthResponseDto | { requiresOtp: true; tempToken: string }> {
    const entity = await this.users.findById(user.id);
    if (entity?.has2FA) {
      const step = await this.auth.begin2faForUserId(user.id);
      return step;
    }
    const result = await this.auth.issueForUserId(user.id, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', result.sessionId, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    const expiresIn = parseDuration(
      this.config.get<string>('jwt.accessExpiration'),
    );
    const dtoOut = new AuthResponseDto({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: this.toUserDto(result.user),
      expiresIn,
    });
    return instanceToPlain(dtoOut) as AuthResponseDto;
  }

  @Get('discord')
  @UseGuards(AuthGuard('discord'))
  @ApiOperation({ summary: 'Initiate Discord OAuth2 login' })
  @ApiResponse({ status: 302, description: 'Redirect to Discord OAuth' })
  discord() {
    return;
  }

  @Get('discord/callback')
  @UseGuards(AuthGuard('discord'))
  @ApiOperation({ summary: 'Discord OAuth2 callback' })
  @ApiResponse({ status: 200, description: 'Discord login successful' })
  async discordCallback(
    @CurrentUser() user: { id: string },
    @Res({ passthrough: true }) res: Response,
    @Req() req: ExpressRequest,
  ): Promise<AuthResponseDto | { requiresOtp: true; tempToken: string }> {
    const entity = await this.users.findById(user.id);
    if (entity?.has2FA) {
      const step = await this.auth.begin2faForUserId(user.id);
      return step;
    }
    const result = await this.auth.issueForUserId(user.id, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('sessionId', result.sessionId, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE ?? '604800000', 10),
    });
    const expiresIn = parseDuration(
      this.config.get<string>('jwt.accessExpiration'),
    );
    const dtoOut = new AuthResponseDto({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: this.toUserDto(result.user),
      expiresIn,
    });
    return instanceToPlain(dtoOut) as AuthResponseDto;
  }
}
