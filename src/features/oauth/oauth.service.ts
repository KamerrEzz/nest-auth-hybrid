import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  ForbiddenException,
  Logger,
  Inject,
} from '@nestjs/common';
import { PrismaRepository } from '../../modules/database/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { REDIS_CLIENT } from '../../modules/redis/redis.constants';
import type Redis from 'ioredis';
import { randomBytes, createHash, randomUUID } from 'crypto';
import * as bcrypt from 'bcrypt';
import { CreateAppDto } from './dto/create-app.dto';

const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'notes'];

// Must match the prefix used by SessionService (modules/session/session.service.ts).
const SESSION_KEY_PREFIX = 'session:';

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly prisma: PrismaRepository,
    private readonly config: ConfigService,
    private readonly jwt: JwtService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  // ── App management ──────────────────────────────────────────────────

  async createApp(userId: string, dto: CreateAppDto) {
    const invalidScope = dto.scopes.find((s) => !ALLOWED_SCOPES.includes(s));
    if (invalidScope)
      throw new BadRequestException(`Scope no soportado: ${invalidScope}`);

    const plainSecret = randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(plainSecret, 10);

    const app = await this.prisma.createOAuthApp({
      name: dto.name,
      description: dto.description,
      redirectUris: dto.redirectUris,
      scopes: dto.scopes,
      userId,
      clientSecret: hashedSecret,
    });

    return { app: { ...app, clientSecret: undefined }, plainSecret };
  }

  async getApps(userId: string) {
    const apps = await this.prisma.findOAuthAppsByUser(userId);
    return apps.map((a: { clientSecret: string }) => ({
      ...a,
      clientSecret: undefined,
    }));
  }

  async deleteApp(appId: string, userId: string) {
    const app = await this.prisma.findOAuthAppById(appId);
    if (!app) throw new NotFoundException('App no encontrada');
    if (app.userId !== userId) throw new ForbiddenException();
    await this.prisma.deleteOAuthApp(appId);
  }

  async regenerateSecret(appId: string, userId: string) {
    const app = await this.prisma.findOAuthAppById(appId);
    if (!app) throw new NotFoundException('App no encontrada');
    if (app.userId !== userId) throw new ForbiddenException();

    const plainSecret = randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(plainSecret, 10);
    await this.prisma.updateOAuthAppSecret(appId, hashedSecret);
    return { plainSecret };
  }

  // ── Authorization endpoint ──────────────────────────────────────────

  async validateAuthRequest(
    clientId: string,
    redirectUri: string,
    scopeStr: string,
  ) {
    const app = await this.prisma.findOAuthAppByClientId(clientId);
    if (!app) throw new BadRequestException('client_id inválido');
    if (!app.redirectUris.includes(redirectUri)) {
      throw new BadRequestException('redirect_uri no registrada');
    }
    const requestedScopes = scopeStr ? scopeStr.split(' ') : ['openid'];
    const invalidScope = requestedScopes.find(
      (s) => !app.scopes.includes(s) && !ALLOWED_SCOPES.includes(s),
    );
    if (invalidScope)
      throw new BadRequestException(`Scope no permitido: ${invalidScope}`);
    return { app, requestedScopes };
  }

  async storeAuthRequest(params: {
    clientId: string;
    redirectUri: string;
    scopes: string[];
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    userId: string;
    appName: string;
  }) {
    const requestId = randomUUID();
    await this.redis.set(
      `oauth_req:${requestId}`,
      JSON.stringify(params),
      'EX',
      300, // 5 min
    );
    return requestId;
  }

  async getAuthRequest(requestId: string) {
    const raw = await this.redis.get(`oauth_req:${requestId}`);
    if (!raw)
      throw new BadRequestException('Solicitud OAuth expirada o inválida');
    return JSON.parse(raw) as {
      clientId: string;
      redirectUri: string;
      scopes: string[];
      state?: string;
      codeChallenge?: string;
      codeChallengeMethod?: string;
      userId: string;
      appName: string;
    };
  }

  async issueAuthCode(requestId: string, userId: string) {
    const req = await this.getAuthRequest(requestId);
    if (req.userId !== userId) throw new ForbiddenException();

    const code = randomBytes(32).toString('hex');
    await this.prisma.createOAuthAuthCode({
      code,
      clientId: req.clientId,
      userId,
      scopes: req.scopes,
      redirectUri: req.redirectUri,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 min
      codeChallenge: req.codeChallenge,
      codeChallengeMethod: req.codeChallengeMethod,
    });

    await this.redis.del(`oauth_req:${requestId}`);

    const redirectUrl = new URL(req.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (req.state) redirectUrl.searchParams.set('state', req.state);
    return redirectUrl.toString();
  }

  /**
   * Reads the session entry stored by SessionService (key `session:<id>`)
   * and returns the associated userId. Used by the /oauth/authorize redirect
   * flow, which cannot easily use HybridAuthGuard because Nest needs to
   * respond with a 302 instead of throwing 401 when the user is not logged in.
   *
   * Validates expiry explicitly in addition to the Redis TTL, matching the
   * behaviour of SessionService.get().
   */
  async getSessionUserId(sessionId: string): Promise<string | null> {
    if (!sessionId || typeof sessionId !== 'string') return null;
    const raw = await this.redis.get(`${SESSION_KEY_PREFIX}${sessionId}`);
    if (!raw) return null;
    try {
      const data = JSON.parse(raw) as {
        userId?: string;
        expiresAt?: number;
      };
      if (data.expiresAt && data.expiresAt < Date.now()) return null;
      return data.userId ?? null;
    } catch (err) {
      this.logger.warn(
        `Malformed session payload for ${sessionId}: ${(err as Error).message}`,
      );
      return null;
    }
  }

  // ── Token endpoint ──────────────────────────────────────────────────

  async exchangeCode(dto: {
    code: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
    codeVerifier?: string;
  }) {
    const authCode = await this.prisma.findOAuthAuthCode(dto.code);
    if (!authCode || authCode.used || authCode.expiresAt < new Date()) {
      throw new BadRequestException('Código inválido o expirado');
    }
    if (authCode.clientId !== dto.clientId)
      throw new BadRequestException('client_id no coincide');
    if (authCode.redirectUri !== dto.redirectUri)
      throw new BadRequestException('redirect_uri no coincide');

    // PKCE validation
    if (authCode.codeChallenge) {
      if (!dto.codeVerifier)
        throw new BadRequestException('code_verifier requerido');
      const valid = this.verifyPkce(
        dto.codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod ?? 'S256',
      );
      if (!valid) throw new BadRequestException('code_verifier inválido');
    } else if (dto.clientSecret) {
      // Confidential client — validate secret
      const app = await this.prisma.findOAuthAppByClientId(dto.clientId);
      if (!app) throw new UnauthorizedException();
      const ok = await bcrypt.compare(dto.clientSecret, app.clientSecret);
      if (!ok) throw new UnauthorizedException('client_secret inválido');
    }

    await this.prisma.markOAuthAuthCodeUsed(authCode.id);
    return this.issueTokens(
      authCode.userId,
      authCode.clientId,
      authCode.scopes,
    );
  }

  async refreshTokenGrant(dto: {
    refreshToken: string;
    clientId: string;
    clientSecret?: string;
  }) {
    const tokenRecord = await this.prisma.findOAuthTokenByRefresh(
      dto.refreshToken,
    );
    if (!tokenRecord || tokenRecord.revoked)
      throw new UnauthorizedException('refresh_token inválido');
    if (tokenRecord.clientId !== dto.clientId)
      throw new UnauthorizedException();

    if (dto.clientSecret) {
      const app = await this.prisma.findOAuthAppByClientId(dto.clientId);
      if (!app) throw new UnauthorizedException();
      const ok = await bcrypt.compare(dto.clientSecret, app.clientSecret);
      if (!ok) throw new UnauthorizedException('client_secret inválido');
    }

    // Revoke old token and issue new ones
    await this.prisma.revokeOAuthToken(tokenRecord.id);
    return this.issueTokens(
      tokenRecord.userId,
      tokenRecord.clientId,
      tokenRecord.scopes,
    );
  }

  async introspect(token: string, clientId: string, clientSecret: string) {
    await this.validateConfidentialClient(clientId, clientSecret);
    const record = await this.prisma.findOAuthTokenByAccess(token);
    if (!record || record.revoked || record.expiresAt < new Date()) {
      return { active: false };
    }
    const user = await this.prisma.findUserById(record.userId);
    return {
      active: true,
      scope: record.scopes.join(' '),
      client_id: record.clientId,
      sub: record.userId,
      exp: Math.floor(record.expiresAt.getTime() / 1000),
      username: user?.email,
    };
  }

  async revoke(token: string, clientId: string, clientSecret: string) {
    await this.validateConfidentialClient(clientId, clientSecret);
    const record =
      (await this.prisma.findOAuthTokenByAccess(token)) ??
      (await this.prisma.findOAuthTokenByRefresh(token));
    if (record && record.clientId === clientId) {
      await this.prisma.revokeOAuthToken(record.id);
    }
    // RFC 7009: always return 200
  }

  async userInfo(accessToken: string) {
    const record = await this.prisma.findOAuthTokenByAccess(accessToken);
    if (!record || record.revoked || record.expiresAt < new Date()) {
      throw new UnauthorizedException('Token inválido o expirado');
    }
    const user = await this.prisma.findUserById(record.userId);
    if (!user) throw new UnauthorizedException();

    const response: Record<string, unknown> = { sub: user.id };
    if (record.scopes.includes('profile')) response.name = user.name;
    if (record.scopes.includes('email')) {
      response.email = user.email;
      response.email_verified = user.emailVerified;
    }
    return response;
  }

  // ── Discovery ───────────────────────────────────────────────────────

  getDiscovery() {
    const issuer =
      this.config.get<string>('app.serverUrl') ?? 'http://localhost:3000';
    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/oauth/userinfo`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      introspection_endpoint: `${issuer}/oauth/introspect`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      scopes_supported: ALLOWED_SCOPES,
      token_endpoint_auth_methods_supported: [
        'client_secret_post',
        'client_secret_basic',
        'none',
      ],
      claims_supported: ['sub', 'email', 'email_verified', 'name'],
      code_challenge_methods_supported: ['S256', 'plain'],
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────

  private async issueTokens(
    userId: string,
    clientId: string,
    scopes: string[],
  ) {
    const jti = randomUUID();
    const expiresIn = 3600; // 1 hour
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    const secret = this.config.get<string>('jwt.secret')!;
    const accessToken = await this.jwt.signAsync(
      {
        sub: userId,
        client_id: clientId,
        scope: scopes.join(' '),
        jti,
        type: 'oauth_access',
      },
      { secret, expiresIn },
    );

    const refreshToken = randomBytes(48).toString('hex');

    await this.prisma.createOAuthToken({
      accessToken,
      refreshToken,
      clientId,
      userId,
      scopes,
      expiresAt,
    });

    const response: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };

    return response;
  }

  private verifyPkce(
    verifier: string,
    challenge: string,
    method: string,
  ): boolean {
    if (method === 'plain') return verifier === challenge;
    const hash = createHash('sha256').update(verifier).digest();
    const computed = hash.toString('base64url');
    return computed === challenge;
  }

  private async validateConfidentialClient(
    clientId: string,
    clientSecret: string,
  ) {
    const app = await this.prisma.findOAuthAppByClientId(clientId);
    if (!app) throw new UnauthorizedException('client_id inválido');
    const ok = await bcrypt.compare(clientSecret, app.clientSecret);
    if (!ok) throw new UnauthorizedException('client_secret inválido');
    return app;
  }
}
