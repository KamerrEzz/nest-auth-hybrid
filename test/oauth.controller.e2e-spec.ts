/* eslint-disable @typescript-eslint/unbound-method */
import request from 'supertest';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { OAuthController } from '../src/features/oauth/oauth.controller';
import { OAuthService } from '../src/features/oauth/oauth.service';
import { PrismaRepository } from '../src/modules/database/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from '../src/modules/session/session.service';
import { TokenService } from '../src/modules/token/token.service';

// Stub guards so Nest doesn't fail on dependency resolution
// The controller uses HybridAuthGuard, CsrfGuard, and RateLimitGuard
// but our tests only target /oauth/token (RateLimitGuard only) and /oauth/introspect (no guards)
jest.mock('../src/common/guards/hybrid-auth.guard.ts', () => ({
  HybridAuthGuard: class {
    canActivate() {
      return true;
    }
  },
}));
jest.mock('../src/common/guards/csrf.guard.ts', () => ({
  CsrfGuard: class {
    canActivate() {
      return true;
    }
  },
}));
jest.mock('../src/common/guards/rate-limit.guard.ts', () => ({
  RateLimitGuard: class {
    canActivate() {
      return true;
    }
  },
}));

// Mock bcrypt so validateConfidentialClient works
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('hashed-secret'),
  compare: jest.fn().mockResolvedValue(true),
}));

describe('OAuthController (e2e)', () => {
  let app: INestApplication;
  let oauthService: OAuthService;
  let prisma: PrismaRepository;

  const mockClientId = 'test-oauth-client';
  const mockClientSecret = 'client-secret-value';
  const mockUserId = 'user-123';

  function buildModule(
    customIntrospectMock?: (
      token: string,
      clientId: string,
      clientSecret: string,
    ) => Promise<any>,
  ) {
    return Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        OAuthService,
        PrismaRepository,
        ConfigService,
        JwtService,
        SessionService,
        TokenService,
      ],
    })
      .overrideProvider(OAuthService)
      .useValue({
        createApp: jest.fn(),
        getApps: jest.fn(),
        deleteApp: jest.fn(),
        regenerateSecret: jest.fn(),
        validateAuthRequest: jest.fn(),
        storeAuthRequest: jest.fn(),
        getAuthRequest: jest.fn(),
        issueAuthCode: jest.fn(),
        getSessionUserId: jest.fn(),
        exchangeCode: jest.fn(),
        refreshTokenGrant: jest.fn(),
        introspect:
          customIntrospectMock ??
          jest.fn().mockResolvedValue({ active: false }),
        revoke: jest.fn(),
        userInfo: jest.fn(),
        getDiscovery: jest.fn(),
        validateConfidentialClient: jest.fn().mockResolvedValue({}),
      })
      .overrideProvider(PrismaRepository)
      .useValue({
        findOAuthAuthCode: jest.fn(),
        findOAuthTokenByAccess: jest.fn(),
        findOAuthTokenByRefresh: jest.fn(),
        findOAuthAppByClientId: jest.fn(),
        findUserById: jest.fn(),
        markOAuthAuthCodeUsed: jest.fn(),
        createOAuthAuthCode: jest.fn(),
        createOAuthToken: jest.fn(),
      })
      .overrideProvider(SessionService)
      .useValue({
        get: jest.fn(),
        touch: jest.fn(),
      })
      .overrideProvider(TokenService)
      .useValue({
        verifyAccess: jest.fn(),
      })
      .overrideProvider(ConfigService)
      .useValue({
        get: jest.fn((key: string) => {
          if (key === 'jwt.secret') return 'jwt-secret';
          if (key === 'app.serverUrl') return 'http://localhost:3000';
          if (key === 'app.frontendUrl') return 'http://localhost:3001';
          if (key === 'jwt.accessExpiration') return '3600';
          if (key === 'jwt.refreshSecret') return 'refresh-secret';
          if (key === 'jwt.refreshExpiration') return '604800';
          return null;
        }),
      })
      .overrideProvider(JwtService)
      .useValue({
        signAsync: jest.fn().mockResolvedValue('mock-access-token'),
        verifyAsync: jest
          .fn()
          .mockResolvedValue({ sub: 'user-123', sid: 'sess-1' }),
      })
      .overrideProvider('REDIS_CLIENT')
      .useValue({
        get: jest.fn(),
        set: jest.fn(),
        setex: jest.fn(),
        del: jest.fn(),
        eval: jest.fn().mockResolvedValue(1),
      });
  }

  beforeEach(async () => {
    const moduleFixture = await buildModule().compile();
    oauthService = moduleFixture.get<OAuthService>(OAuthService);
    prisma = moduleFixture.get<PrismaRepository>(PrismaRepository);

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /oauth/token', () => {
    describe('authorization_code grant', () => {
      it('should exchange auth code with PKCE (happy path via controller)', async () => {
        oauthService.exchangeCode.mockResolvedValue({
          access_token: 'mock-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'mock-refresh-token',
          scope: 'openid profile',
        });

        const response = await request(app.getHttpServer())
          .post('/oauth/token')
          .type('form')
          .send({
            grant_type: 'authorization_code',
            client_id: mockClientId,
            redirect_uri: 'http://localhost:3001/callback',
            code: 'auth-code-value',
            code_verifier:
              'dbd10d2e1d58f0326314a0479ca51a796534a0646ed57dfc6f80a7965f0e3e2f',
          });

        expect(response.status).toBe(200);
        expect(oauthService.exchangeCode).toHaveBeenCalled();
      });

      it('should pass client_secret with confidential client', async () => {
        oauthService.exchangeCode.mockResolvedValue({
          access_token: 'mock',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'mock',
          scope: 'openid',
        });

        const response = await request(app.getHttpServer())
          .post('/oauth/token')
          .type('form')
          .send({
            grant_type: 'authorization_code',
            client_id: mockClientId,
            client_secret: mockClientSecret,
            redirect_uri: 'http://localhost:3001/callback',
            code: 'code',
            code_verifier: 'verifier',
          });

        expect(response.status).toBe(200);
        expect(oauthService.exchangeCode).toHaveBeenCalledWith(
          expect.objectContaining({
            clientId: mockClientId,
            clientSecret: mockClientSecret,
          }),
        );
      });
    });

    describe('refresh_token grant', () => {
      it('should call refreshTokenGrant for refresh_token grant_type', async () => {
        oauthService.refreshTokenGrant.mockResolvedValue({
          access_token: 'new-mock',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new-refresh',
          scope: 'openid',
        });

        const response = await request(app.getHttpServer())
          .post('/oauth/token')
          .type('form')
          .send({
            grant_type: 'refresh_token',
            refresh_token: 'old-refresh',
            client_id: mockClientId,
            client_secret: mockClientSecret,
          });

        expect(response.status).toBe(200);
        expect(oauthService.refreshTokenGrant).toHaveBeenCalled();
      });
    });

    describe('unsupported grant_type', () => {
      it('should return 400 for unsupported grant_type', async () => {
        const response = await request(app.getHttpServer())
          .post('/oauth/token')
          .type('form')
          .send({
            grant_type: 'password',
            client_id: mockClientId,
          });

        expect(response.status).toBe(400);
        expect(response.body.statusCode).toBe(400);
      });
    });
  });

  describe('POST /oauth/introspect', () => {
    it('should return active:true for a valid token via the introspect mock', async () => {
      const validResult = {
        active: true,
        scope: 'openid profile',
        client_id: mockClientId,
        sub: mockUserId,
        exp: Math.floor((Date.now() + 3600000) / 1000),
        username: 'test@example.com',
      };

      const moduleFixture = await buildModule(
        async (_token: string, _clientId: string, _clientSecret: string) =>
          validResult,
      ).compile();

      oauthService = moduleFixture.get<OAuthService>(OAuthService);
      app = moduleFixture.createNestApplication();
      app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
      await app.init();

      const response = await request(app.getHttpServer())
        .post('/oauth/introspect')
        .send({
          token: 'valid-access-token',
          client_id: mockClientId,
          client_secret: mockClientSecret,
        });

      expect(response.status).toBe(200);
      expect(response.body.active).toBe(true);
      expect(response.body.client_id).toBe(mockClientId);
      expect(response.body.sub).toBe(mockUserId);

      await app.close();
    });

    it('should return active:false for a non-existent token', async () => {
      const moduleFixture = await buildModule(async () => ({
        active: false,
      })).compile();

      oauthService = moduleFixture.get<OAuthService>(OAuthService);
      app = moduleFixture.createNestApplication();
      app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
      await app.init();

      const response = await request(app.getHttpServer())
        .post('/oauth/introspect')
        .send({
          token: 'nonexistent-token',
          client_id: mockClientId,
          client_secret: mockClientSecret,
        });

      expect(response.status).toBe(200);
      expect(response.body.active).toBe(false);

      await app.close();
    });
  });
});
