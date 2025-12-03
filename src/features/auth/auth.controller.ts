import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Res,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Delete, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
// import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
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
import type { Request as ExpressRequest } from 'express';
import type { SessionEntity } from '../../modules/session/entities/session.entity';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly users: UserService,
    private readonly config: ConfigService,
  ) {}

  private parseDuration(value: string | number | undefined) {
    if (typeof value === 'number') return value;
    if (!value) return 0;
    const s = String(value);
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    const m = s.match(/^(\d+)([smhd])$/);
    if (!m) return 0;
    const num = parseInt(m[1], 10);
    const unit = m[2];
    const map = { s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>;
    return num * map[unit];
  }

  private toUserDto(entity: {
    id: string;
    email: string;
    name?: string | null;
    createdAt?: Date;
  }) {
    return new UserResponseDto({
      id: entity.id,
      email: entity.email,
      name: entity.name ?? undefined,
      createdAt: entity.createdAt ?? new Date(),
    });
  }

  @Post('register')
  @HttpCode(201)
  @RateLimit(5, 300)
  @UseGuards(RateLimitGuard)
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
    const expiresIn = this.parseDuration(
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
    const expiresIn = this.parseDuration(
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

  @Get('2fa/status')
  @UseGuards(HybridAuthGuard)
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
  @UseGuards(HybridAuthGuard)
  async disable2fa(
    @CurrentUser() user: { id: string },
    @Body() body: { totpCode?: string; backupCode?: string },
  ) {
    return this.auth.disable2fa(user.id, body);
  }

  @Post('2fa/cancel')
  @UseGuards(HybridAuthGuard)
  async cancel2fa(@CurrentUser() user: { id: string }) {
    // Cancelar solo si no está confirmado aún
    return this.auth.disable2fa(user.id, {});
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

  @Post('change-password')
  @UseGuards(HybridAuthGuard, CsrfGuard)
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
  async refresh(@Body() dto: RefreshTokenDto, @Req() req: ExpressRequest) {
    return this.auth.refresh(dto.refreshToken, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
  }

  @Get('me')
  @UseGuards(HybridAuthGuard)
  async me(@CurrentUser() user?: { id: string }) {
    if (!user) return null;
    const entity = await this.users.findById(user.id);
    return entity
      ? (instanceToPlain(this.toUserDto(entity)) as UserResponseDto)
      : null;
  }

  @Post('logout')
  @UseGuards(HybridAuthGuard)
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('sessionId');
    return { ok: true };
  }

  @Get('sessions')
  @UseGuards(HybridAuthGuard)
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
  @UseGuards(HybridAuthGuard)
  async revokeAll(@CurrentUser() user?: { id: string }) {
    if (!user) return { ok: false };
    await this.auth.revokeAllSessions(user.id);
    return { ok: true };
  }

  @Delete('sessions/:id')
  @UseGuards(HybridAuthGuard)
  async revoke(@Param('id') id: string) {
    await this.auth.revokeSession(id);
    return { ok: true };
  }

  @Delete('sessions/others')
  @UseGuards(HybridAuthGuard)
  async revokeOthers(
    @CurrentUser() user: { id: string },
    @Req() req: ExpressRequest,
  ) {
    const rawSid: unknown = req.cookies?.sessionId;
    const currentId = typeof rawSid === 'string' ? rawSid : '';
    await this.auth.revokeOtherSessions(user.id, currentId);
    return { ok: true };
  }
  @Get('google')
  @UseGuards(AuthGuard('google'))
  google() {
    return;
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
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
    const expiresIn = this.parseDuration(
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
  discord() {
    return;
  }

  @Get('discord/callback')
  @UseGuards(AuthGuard('discord'))
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
    const expiresIn = this.parseDuration(
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
