/* eslint-disable @typescript-eslint/unbound-method */
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
import { PrismaRepository } from '../../../modules/database/prisma/prisma.service';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let prisma: jest.Mocked<PrismaRepository>;

  const mockConfig = {
    get: jest.fn((key: string) => {
      if (key === 'jwt.secret') return 'test-secret';
      return null;
    }),
  } as unknown as ConfigService;

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    password: 'hashed',
    name: 'Test User',
    has2FA: false,
    totpSecret: null,
    backupCodes: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLoginAt: null,
    emailVerified: true,
  };

  beforeEach(() => {
    prisma = {
      findUserById: jest.fn(),
    } as unknown as jest.Mocked<PrismaRepository>;

    strategy = new JwtStrategy(mockConfig, prisma);
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  describe('validate', () => {
    it('should return user when user exists in DB', async () => {
      const payload = { sub: 'user-123' };
      prisma.findUserById.mockResolvedValueOnce(mockUser);

      const result = await strategy.validate(payload);

      expect(result).toEqual(mockUser);
      expect(prisma.findUserById).toHaveBeenCalledWith('user-123');
    });

    it('should throw UnauthorizedException when user not found in DB', async () => {
      const payload = { sub: 'nonexistent-user' };
      prisma.findUserById.mockResolvedValueOnce(null);

      await expect(strategy.validate(payload)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prisma.findUserById).toHaveBeenCalledWith('nonexistent-user');
    });

    it('should throw UnauthorizedException when user is deleted from DB', async () => {
      const payload = { sub: 'deleted-user-456' };
      prisma.findUserById.mockResolvedValueOnce(null);

      await expect(strategy.validate(payload)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prisma.findUserById).toHaveBeenCalledWith('deleted-user-456');
    });
  });
});
