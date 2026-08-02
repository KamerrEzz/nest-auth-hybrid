import { ExecutionContext } from '@nestjs/common';
import { HybridAuthGuard } from './hybrid-auth.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { SessionAuthGuard } from './session-auth.guard';

describe('HybridAuthGuard', () => {
  let guard: HybridAuthGuard;
  let jwtGuard: JwtAuthGuard;
  let sessionGuard: SessionAuthGuard;
  let jwtCanActivate: jest.Mock<Promise<boolean>, [ExecutionContext]>;
  let sessionCanActivate: jest.Mock<Promise<boolean>, [ExecutionContext]>;

  beforeEach(() => {
    jwtCanActivate = jest.fn();
    sessionCanActivate = jest.fn();
    jwtGuard = { canActivate: jwtCanActivate } as unknown as JwtAuthGuard;
    sessionGuard = {
      canActivate: sessionCanActivate,
    } as unknown as SessionAuthGuard;
    guard = new HybridAuthGuard(jwtGuard, sessionGuard);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    let ctx: ExecutionContext;

    beforeEach(() => {
      ctx = {
        switchToHttp: jest
          .fn()
          .mockReturnValue({ getResponse: jest.fn(), getRequest: jest.fn() }),
      } as unknown as ExecutionContext;
    });

    it('should return true when JwtAuthGuard succeeds', async () => {
      jwtCanActivate.mockResolvedValue(true);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(jwtCanActivate).toHaveBeenCalledWith(ctx);
      expect(sessionCanActivate).not.toHaveBeenCalled();
    });

    it('should fall back to SessionAuthGuard when JwtAuthGuard returns false', async () => {
      jwtCanActivate.mockResolvedValue(false);
      sessionCanActivate.mockResolvedValue(true);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(jwtCanActivate).toHaveBeenCalledWith(ctx);
      expect(sessionCanActivate).toHaveBeenCalledWith(ctx);
    });

    it('should fall back to SessionAuthGuard when JwtAuthGuard throws', async () => {
      jwtCanActivate.mockRejectedValue(new Error('jwt error'));
      sessionCanActivate.mockResolvedValue(true);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(jwtCanActivate).toHaveBeenCalledWith(ctx);
      expect(sessionCanActivate).toHaveBeenCalledWith(ctx);
    });

    it('should return false when both guards fail', async () => {
      jwtCanActivate.mockResolvedValue(false);
      sessionCanActivate.mockResolvedValue(false);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(false);
      expect(jwtCanActivate).toHaveBeenCalledWith(ctx);
      expect(sessionCanActivate).toHaveBeenCalledWith(ctx);
    });

    it('should propagate error when SessionAuthGuard throws', async () => {
      jwtCanActivate.mockResolvedValue(false);
      sessionCanActivate.mockRejectedValue(new Error('session error'));

      await expect(guard.canActivate(ctx)).rejects.toThrow('session error');
    });
  });
});
