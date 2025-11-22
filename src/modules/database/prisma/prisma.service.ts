import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
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

  async enable2FA(
    userId: string,
    totpSecretEnc: string,
    backupCodes: string[],
  ) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: false, totpSecret: totpSecretEnc, backupCodes },
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

  async confirm2FA(userId: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: true },
    });
    return result;
  }

  async cancel2FA(userId: string) {
    const result = await this.user.update({
      where: { id: userId },
      data: { has2FA: false, totpSecret: null, backupCodes: [] },
    });
    return result;
  }
}
