import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Query,
  Param,
  Res,
  Req,
  UseGuards,
  HttpCode,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { CreateAppDto } from './dto/create-app.dto';
import { TokenDto } from './dto/token.dto';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';
import { CsrfGuard } from '../../common/guards/csrf.guard';
import { RateLimitGuard } from '../../common/guards/rate-limit.guard';
import { RateLimit } from '../../common/decorators/rate-limit.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { ConfigService } from '@nestjs/config';
import type { Response, Request } from 'express';

@Controller()
export class OAuthController {
  constructor(
    private readonly oauth: OAuthService,
    private readonly config: ConfigService,
  ) {}

  // ── App management ──────────────────────────────────────────────────

  @Post('oauth/apps')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  async createApp(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateAppDto,
  ) {
    return this.oauth.createApp(user.id, dto);
  }

  @Get('oauth/apps')
  @UseGuards(HybridAuthGuard)
  async getApps(@CurrentUser() user: { id: string }) {
    return this.oauth.getApps(user.id);
  }

  @Delete('oauth/apps/:id')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  async deleteApp(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
  ) {
    await this.oauth.deleteApp(id, user.id);
    return { ok: true };
  }

  @Post('oauth/apps/:id/regenerate-secret')
  @UseGuards(HybridAuthGuard, CsrfGuard)
  async regenerateSecret(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
  ) {
    return this.oauth.regenerateSecret(id, user.id);
  }

  // ── Authorization endpoint ──────────────────────────────────────────

  @Get('oauth/authorize')
  @RateLimit(20, 60)
  @UseGuards(RateLimitGuard)
  async authorize(
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('scope') scope: string,
    @Query('state') state: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    if (responseType !== 'code')
      throw new BadRequestException('response_type debe ser "code"');
    if (!clientId || !redirectUri)
      throw new BadRequestException('Parámetros requeridos faltantes');

    const { app, requestedScopes } = await this.oauth.validateAuthRequest(
      clientId,
      redirectUri,
      scope ?? 'openid',
    );

    // Check if user is authenticated via session cookie
    const cookies = req.cookies as Record<string, unknown> | undefined;
    const sessionId = cookies?.sessionId;
    let userId: string | null = null;

    if (typeof sessionId === 'string' && sessionId) {
      userId = await this.oauth.getSessionUserId(sessionId);
    }

    const frontendUrl =
      this.config.get<string>('app.frontendUrl') ?? 'http://localhost:3001';

    if (!userId) {
      // Redirect to login, preserve oauth params
      const oauthParams = new URLSearchParams({
        response_type: responseType,
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: scope ?? 'openid',
        ...(state && { state }),
        ...(codeChallenge && { code_challenge: codeChallenge }),
        ...(codeChallengeMethod && {
          code_challenge_method: codeChallengeMethod,
        }),
      });
      return res.redirect(
        `${frontendUrl}/login?from=${encodeURIComponent('/oauth/authorize?' + oauthParams.toString())}`,
      );
    }

    const requestId = await this.oauth.storeAuthRequest({
      clientId,
      redirectUri,
      scopes: requestedScopes,
      state,
      codeChallenge,
      codeChallengeMethod,
      userId,
      appName: app.name,
    });

    const consentParams = new URLSearchParams({
      request_id: requestId,
      app_name: app.name,
      scope: requestedScopes.join(' '),
      client_id: clientId,
    });
    return res.redirect(
      `${frontendUrl}/oauth/consent?${consentParams.toString()}`,
    );
  }

  @Get('oauth/consent/:requestId')
  async getConsentInfo(@Param('requestId') requestId: string) {
    return this.oauth.getAuthRequest(requestId);
  }

  @Post('oauth/authorize')
  @HttpCode(200)
  @UseGuards(HybridAuthGuard, CsrfGuard)
  async grantConsent(
    @CurrentUser() user: { id: string },
    @Body() body: { request_id: string; approved: boolean },
  ) {
    if (!body.approved) {
      const req = await this.oauth.getAuthRequest(body.request_id);
      const url = new URL(req.redirectUri);
      url.searchParams.set('error', 'access_denied');
      if (req.state) url.searchParams.set('state', req.state);
      return { redirectTo: url.toString() };
    }
    const redirectTo = await this.oauth.issueAuthCode(body.request_id, user.id);
    return { redirectTo };
  }

  // ── Token endpoint ──────────────────────────────────────────────────

  @Post('oauth/token')
  @HttpCode(200)
  @RateLimit(20, 60)
  @UseGuards(RateLimitGuard)
  async token(@Body() dto: TokenDto, @Req() req: Request) {
    // Support client_secret_basic (Authorization: Basic base64(id:secret))
    let clientId = dto.client_id;
    let clientSecret = dto.client_secret;
    const authHeader = req.headers.authorization;
    if (!clientId && authHeader?.startsWith('Basic ')) {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString(
        'utf8',
      );
      const sep = decoded.indexOf(':');
      if (sep > 0) {
        clientId = decodeURIComponent(decoded.slice(0, sep));
        clientSecret = decodeURIComponent(decoded.slice(sep + 1));
      }
    }
    if (!clientId) throw new BadRequestException('client_id requerido');

    if (dto.grant_type === 'authorization_code') {
      if (!dto.code || !dto.redirect_uri)
        throw new BadRequestException('Parámetros requeridos faltantes');
      return this.oauth.exchangeCode({
        code: dto.code,
        clientId,
        clientSecret,
        redirectUri: dto.redirect_uri,
        codeVerifier: dto.code_verifier,
      });
    }
    if (dto.grant_type === 'refresh_token') {
      if (!dto.refresh_token)
        throw new BadRequestException('refresh_token requerido');
      return this.oauth.refreshTokenGrant({
        refreshToken: dto.refresh_token,
        clientId,
        clientSecret,
      });
    }
    throw new BadRequestException('grant_type no soportado');
  }

  // ── Resource endpoints ──────────────────────────────────────────────

  @Post('oauth/introspect')
  @HttpCode(200)
  async introspect(
    @Body() body: { token: string; client_id: string; client_secret: string },
  ) {
    if (!body.token || !body.client_id || !body.client_secret) {
      throw new BadRequestException('Parámetros requeridos faltantes');
    }
    return this.oauth.introspect(
      body.token,
      body.client_id,
      body.client_secret,
    );
  }

  @Post('oauth/revoke')
  @HttpCode(200)
  async revoke(
    @Body() body: { token: string; client_id: string; client_secret: string },
  ) {
    if (!body.token || !body.client_id || !body.client_secret) {
      throw new BadRequestException('Parámetros requeridos faltantes');
    }
    await this.oauth.revoke(body.token, body.client_id, body.client_secret);
    return {};
  }

  @Get('oauth/userinfo')
  async userInfo(@Req() req: Request) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer '))
      throw new UnauthorizedException('Bearer token requerido');
    const token = auth.slice(7);
    return this.oauth.userInfo(token);
  }

  // ── Discovery ───────────────────────────────────────────────────────

  @Get('.well-known/openid-configuration')
  discovery() {
    return this.oauth.getDiscovery();
  }

  @Get('.well-known/jwks.json')
  jwks() {
    // Currently HS256 — no public keys to expose
    return { keys: [] };
  }
}
