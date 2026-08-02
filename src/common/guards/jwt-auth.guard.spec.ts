/* eslint-disable @typescript-eslint/unbound-method */
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { TokenService } from '../../modules/token/token.service';
import { SessionService } from '../../modules/session/session.service';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let tokenService: TokenService;
  let sessionService: SessionService;
  let mockReq: any;

  const validSid = 'session-abc-123';
  const validUserSub = 'user-123';

  beforeEach(() => {
    tokenService = { verifyAccess: jest.fn() } as unknown as TokenService;
    sessionService = {
      get: jest.fn().mockResolvedValue({
        id: validSid,
        userId: validUserSub,
        expiresAt: Date.now() + 60000,
      }),
      touch: jest.fn().mockResolvedValue(undefined),
    } as unknown as SessionService;

    guard = new JwtAuthGuard(tokenService, sessionService);

    mockReq = {
      headers: {},
      user: undefined,
    };
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should return true with valid Bearer token, valid sid, and valid session', async () => {
      const accessToken = 'valid.jwt.token';
      mockReq.headers['authorization'] = `Bearer ${accessToken}`;

      tokenService.verifyAccess.mockResolvedValueOnce({
        sub: validUserSub,
        sid: validSid,
      });
      sessionService.get.mockResolvedValueOnce({
        id: validSid,
        userId: validUserSub,
        expiresAt: Date.now() + 60000,
      });

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(tokenService.verifyAccess).toHaveBeenCalledWith(accessToken);
      expect(sessionService.get).toHaveBeenCalledWith(validSid);
      expect(sessionService.touch).toHaveBeenCalledWith(validSid);
      expect(mockReq.user).toEqual({ id: validUserSub });
    });

    it('should throw UnauthorizedException when no Authorization header', async () => {
      delete mockReq.headers['authorization'];

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(tokenService.verifyAccess).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when Authorization header is empty string', async () => {
      mockReq.headers['authorization'] = '';

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(tokenService.verifyAccess).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when token is not Bearer format', async () => {
      mockReq.headers['authorization'] = 'Basic dXNlcjpwYXNz';

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(tokenService.verifyAccess).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when sid is missing from payload', async () => {
      mockReq.headers['authorization'] = 'Bearer token-no-sid';

      tokenService.verifyAccess.mockResolvedValueOnce({ sub: validUserSub });

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(tokenService.verifyAccess).toHaveBeenCalledWith('token-no-sid');
      expect(sessionService.get).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when session not found in Redis', async () => {
      mockReq.headers['authorization'] = 'Bearer some-token';

      tokenService.verifyAccess.mockResolvedValueOnce({
        sub: validUserSub,
        sid: validSid,
      });
      sessionService.get.mockResolvedValueOnce(null);

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(sessionService.touch).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when token verification fails', async () => {
      mockReq.headers['authorization'] = 'Bearer invalid-token';

      tokenService.verifyAccess.mockRejectedValueOnce(
        new Error('invalid token'),
      );

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(sessionService.get).not.toHaveBeenCalled();
      expect(sessionService.touch).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when session.get throws', async () => {
      mockReq.headers['authorization'] = 'Bearer valid-token';

      tokenService.verifyAccess.mockResolvedValueOnce({
        sub: validUserSub,
        sid: validSid,
      });
      sessionService.get.mockRejectedValueOnce(
        new Error('redis connection error'),
      );

      const ctx = {
        switchToHttp: () => ({ getRequest: () => mockReq }),
      } as unknown as ExecutionContext;

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
