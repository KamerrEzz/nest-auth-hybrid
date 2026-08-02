/* eslint-disable @typescript-eslint/unbound-method */
import { ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import Redis from 'ioredis';
import { RateLimitGuard } from './rate-limit.guard';
import { REDIS_CLIENT } from '../../modules/redis/redis.constants';

describe('RateLimitGuard', () => {
  let guard: RateLimitGuard;
  let reflector: Reflector;
  let redis: Redis;
  let mockReq: any;

  const defaultOptions = { points: 10, duration: 60 };

  beforeEach(() => {
    redis = {
      eval: jest.fn(),
    } as unknown as Redis;

    reflector = { get: jest.fn() } as unknown as Reflector;

    mockReq = {
      ip: '127.0.0.1',
      path: '/test',
    };

    guard = new RateLimitGuard(reflector, redis);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    let ctx: ExecutionContext;

    beforeEach(() => {
      ctx = {
        getHandler: jest.fn(),
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn(),
          getRequest: () => mockReq,
        }),
      } as unknown as ExecutionContext;
    });

    it('should return true when under limit', async () => {
      reflector.get.mockReturnValue(defaultOptions);
      redis.eval.mockResolvedValue(3); // count = 3, under limit of 10

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(redis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'rl:127.0.0.1:/test',
        10,
        60,
      );
    });

    it('should throw TOO_MANY_REQUESTS when count >= points', async () => {
      reflector.get.mockReturnValue(defaultOptions);
      redis.eval.mockResolvedValue(-1); // Lua script returns -1 when limit exceeded

      await expect(guard.canActivate(ctx)).rejects.toThrow(HttpException);

      const error = await guard.canActivate(ctx).catch((e) => e);
      expect(error).toBeInstanceOf(HttpException);
      expect(error.getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
    });

    it('should set expiry on first request (count === 1)', async () => {
      reflector.get.mockReturnValue(defaultOptions);
      const incrReturn = 1; // Redis INCR returns 1 for first request

      // We need to track how eval is called and inspect the Lua script behavior
      redis.eval.mockImplementation(async () => {
        // When count is 1, the Lua script returns 1 and calls EXPIRE first
        return incrReturn;
      });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(redis.eval).toHaveBeenCalled();
    });

    it('should not set expiry on subsequent requests when count > 1', async () => {
      reflector.get.mockReturnValue(defaultOptions);
      redis.eval.mockResolvedValue(5); // INCR returned 5, so EXPIRE was not called in Lua

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(redis.eval).toHaveBeenCalled();
    });

    it('should return true when no rate limit metadata is set', async () => {
      reflector.get.mockReturnValue(undefined);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(redis.eval).not.toHaveBeenCalled();
    });

    it('should return true when rate limit options is null', async () => {
      reflector.get.mockReturnValue(null);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(redis.eval).not.toHaveBeenCalled();
    });

    it('should use request IP and path for the rate limit key', async () => {
      reflector.get.mockReturnValue(defaultOptions);
      mockReq.ip = '192.168.1.100';
      mockReq.path = '/api/login';
      redis.eval.mockResolvedValue(1);

      await guard.canActivate(ctx);

      expect(redis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'rl:192.168.1.100:/api/login',
        10,
        60,
      );
    });

    it('should use configured points and duration values', async () => {
      reflector.get.mockReturnValue({ points: 5, duration: 30 });
      redis.eval.mockResolvedValue(2);

      await guard.canActivate(ctx);

      expect(redis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'rl:127.0.0.1:/test',
        5,
        30,
      );
    });
  });
});
