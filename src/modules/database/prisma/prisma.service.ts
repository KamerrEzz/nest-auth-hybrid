import { Injectable } from '@nestjs/common';
import { PrismaClient, Prisma } from '@prisma/client';
import type { User } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {}

export interface CreateUserInput {
  email: string;
  password: string;
  name?: string;
}

@Injectable()
export class PrismaRepository extends PrismaService {
  async createUser(data: CreateUserInput): Promise<User> {
    const result = await this.user.create({ data });
    return result;
  }
  async findUserByEmail(email: string): Promise<User | null> {
    const result = await this.user.findUnique({ where: { email } });
    return result ?? null;
  }
  async findUserById(id: string): Promise<User | null> {
    const result = await this.user.findUnique({ where: { id } });
    return result ?? null;
  }

  async enable2FA(userId: string, totpSecretEnc: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: false, totpSecret: totpSecretEnc, backupCodes: [] },
    });
    return result;
  }

  async disable2FA(userId: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: false, totpSecret: null, backupCodes: [] },
    });
    return result;
  }

  async updateBackupCodes(userId: string, backupCodes: string[]) {
    const result = await this.user.update({
      where: { id: userId },
      data: { backupCodes },
    });
    return result;
  }

  async updateUserPassword(userId: string, password: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { password },
    });
    return result;
  }

  async confirm2FA(userId: string, backupCodes: string[]) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: true, backupCodes },
    });
    return result;
  }

  async verifyUserEmail(userId: string) {
    return this.user.update({
      where: { id: userId },
      data: { emailVerified: true },
    });
  }

  async cancel2FA(userId: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: false, totpSecret: null, backupCodes: [] },
    });
    return result;
  }

  async createAuditLog(data: {
    userId?: string;
    action: string;
    ipAddress?: string;
    userAgent?: string;
    metadata?: Record<string, unknown>;
    severity: string;
  }) {
    return this.auditLog.create({
      data: {
        ...data,
        metadata: data.metadata as Prisma.InputJsonValue | undefined,
      },
    });
  }

  // ── OAuth App ──────────────────────────────────────────────────────
  async createOAuthApp(data: {
    name: string;
    description?: string;
    redirectUris: string[];
    scopes: string[];
    userId: string;
    clientSecret: string;
  }) {
    return this.oAuthApp.create({ data });
  }

  async findOAuthAppsByUser(userId: string) {
    return this.oAuthApp.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOAuthAppById(id: string) {
    return this.oAuthApp.findUnique({ where: { id } });
  }

  async findOAuthAppByClientId(clientId: string) {
    return this.oAuthApp.findUnique({ where: { clientId } });
  }

  async deleteOAuthApp(id: string) {
    return this.oAuthApp.delete({ where: { id } });
  }

  async updateOAuthAppSecret(id: string, clientSecret: string) {
    return this.oAuthApp.update({ where: { id }, data: { clientSecret } });
  }

  // ── OAuth Auth Code ────────────────────────────────────────────────
  async createOAuthAuthCode(data: {
    code: string;
    clientId: string;
    userId: string;
    scopes: string[];
    redirectUri: string;
    expiresAt: Date;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }) {
    return this.oAuthAuthCode.create({ data });
  }

  async findOAuthAuthCode(code: string) {
    return this.oAuthAuthCode.findUnique({ where: { code } });
  }

  async markOAuthAuthCodeUsed(id: string) {
    return this.oAuthAuthCode.update({ where: { id }, data: { used: true } });
  }

  // ── OAuth Token ────────────────────────────────────────────────────
  async createOAuthToken(data: {
    accessToken: string;
    refreshToken: string;
    clientId: string;
    userId: string;
    scopes: string[];
    expiresAt: Date;
  }) {
    return this.oAuthToken.create({ data });
  }

  async findOAuthTokenByAccess(accessToken: string) {
    return this.oAuthToken.findUnique({ where: { accessToken } });
  }

  async findOAuthTokenByRefresh(refreshToken: string) {
    return this.oAuthToken.findUnique({ where: { refreshToken } });
  }

  async revokeOAuthToken(id: string) {
    return this.oAuthToken.update({ where: { id }, data: { revoked: true } });
  }
}
