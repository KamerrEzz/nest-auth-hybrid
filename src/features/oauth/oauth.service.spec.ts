/* eslint-disable @typescript-eslint/unbound-method */
import { Test, TestingModule } from '@nestjs/testing';
import { OAuthService } from './oauth.service';
import { PrismaRepository } from '../../modules/database/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { REDIS_CLIENT } from '../../modules/redis/redis.constants';
import type Redis from 'ioredis';
import { createHash, randomBytes } from 'crypto';

describe('OAuthService', () => {
  let service: OAuthService;
  let prisma: PrismaRepository;
  let moduleRef: TestingModule;

  const mockClientId = 'test-client';
  const mockClientSecret = 'client-secret-value';
  const mockUserId = 'user-123';

  beforeEach(async () => {
    moduleRef = await Test.createTestingModule({
      providers: [
        OAuthService,
        PrismaRepository,
        ConfigService,
        JwtService,
        {
          provide: REDIS_CLIENT,
          useValue: {
            get: jest.fn(),
            set: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
          },
        },
      ],
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
      .overrideProvider(ConfigService)
      .useValue({
        get: (key: string) => {
          if (key === 'jwt.secret') return 'jwt-secret';
          if (key === 'app.serverUrl') return 'http://localhost:3000';
          return null;
        },
      })
      .overrideProvider(JwtService)
      .useValue({
        signAsync: jest.fn().mockResolvedValue('mock-token'),
      })
      .compile();

    // Extract the actual TestingModule from TestingModuleBuilder
    service = moduleRef.get<OAuthService>(OAuthService);
    prisma = moduleRef.get<PrismaRepository>(PrismaRepository);
    jest.clearAllMocks();
  });

  // ── PKCE Verification (pure crypto, no bcrypt) ───────────────────

  describe('verifyPkce', () => {
    it('should return true for valid S256 challenge', () => {
      const verifier = 'dbd10d2e1d58f0326314a0479ca51a796534a0646ed57dfc6f80a7965f0e3e2f';
      const hash = createHash('sha256').update(verifier).digest();
      const challenge = hash.toString('base64url');

      const result = service['verifyPkce'](verifier, challenge, 'S256');
      expect(result).toBe(true);
    });

    it('should return true for valid plain challenge', () => {
      const verifier = 'my-verifier';
      const result = service['verifyPkce'](verifier, verifier, 'plain');
      expect(result).toBe(true);
    });

    it('should return false for invalid S256 challenge', () => {
      const result = service['verifyPkce']('verifier', 'invalid-challenge', 'S256');
      expect(result).toBe(false);
    });

    it('should return false for invalid plain challenge', () => {
      const result = service['verifyPkce']('a', 'b', 'plain');
      expect(result).toBe(false);
    });
  });

  // ── Introspection ──────────────────────────────────────────────────
  // OAuthService imports bcrypt directly. The introspect endpoint calls
  // validateConfidentialClient() which uses bcrypt.compare(). Since we
  // cannot intercept bcrypt through Nest DI, we stub validateConfidentialClient
  // to bypass it entirely.

  describe('introspect', () => {
    const mockValidToken = {
      id: 'token-1',
      accessToken: 'valid-access-token',
      clientId: mockClientId,
      userId: mockUserId,
      scopes: ['openid', 'profile'],
      expiresAt: new Date(Date.now() + 3600000),
      revoked: false,
    } as any;

    beforeEach(() => {
      // Stub internal client validation so we can test the token lookup logic
      jest.spyOn(service, 'validateConfidentialClient' as any)
        .mockResolvedValue({
          id: 'app-1',
          clientId: mockClientId,
          clientSecret: '$2b$10$hashed-secret',
        });
    });

    it('should return active:true for valid token', async () => {
      prisma.findOAuthTokenByAccess.mockResolvedValue(mockValidToken);
      prisma.findUserById.mockResolvedValue({ id: mockUserId, email: 'test@example.com' });

      const result = await service.introspect(
        'valid-access-token',
        mockClientId,
        mockClientSecret,
      );

      expect(result.active).toBe(true);
      expect(result.scope).toBe('openid profile');
      expect(result.client_id).toBe(mockClientId);
    });

    it('should return active:false for revoked token', async () => {
      prisma.findOAuthTokenByAccess.mockResolvedValue({ ...mockValidToken, revoked: true });

      const result = await service.introspect(
        'valid-access-token',
        mockClientId,
        mockClientSecret,
      );

      expect(result.active).toBe(false);
    });

    it('should return active:false for expired token', async () => {
      prisma.findOAuthTokenByAccess.mockResolvedValue({ ...mockValidToken, expiresAt: new Date(Date.now() - 1000) });

      const result = await service.introspect(
        'valid-access-token',
        mockClientId,
        mockClientSecret,
      );

      expect(result.active).toBe(false);
    });

    it('should return active:false for non-existent token', async () => {
      prisma.findOAuthTokenByAccess.mockResolvedValue(null);

      const result = await service.introspect(
        'nonexistent-token',
        mockClientId,
        mockClientSecret,
      );

      expect(result.active).toBe(false);
    });
  });
});