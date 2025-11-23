import { Injectable } from '@nestjs/common';
import { PrismaRepository } from '../database/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import type { UserEntity } from '../../common/types/auth.types';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaRepository,
    private config: ConfigService,
  ) {}

  async create(data: CreateUserDto): Promise<UserEntity> {
    const rounds = this.config.get<number>('security.bcryptRounds') ?? 12;
    const password = await bcrypt.hash(data.password, rounds);
    return await this.prisma.createUser({
      email: data.email,
      password,
      name: data.name,
    });
  }

  async findByEmail(email: string): Promise<UserEntity | null> {
    return await this.prisma.findUserByEmail(email);
  }

  async findById(id: string): Promise<UserEntity | null> {
    return await this.prisma.findUserById(id);
  }

  async enable2FA(userId: string, totpSecretEnc: string) {
    await this.prisma.enable2FA(userId, totpSecretEnc);
  }

  async disable2FA(userId: string) {
    await this.prisma.disable2FA(userId);
  }

  async consumeBackupCode(userId: string, code: string) {
    const user = await this.findById(userId);
    if (!user || !user.backupCodes || user.backupCodes.length === 0)
      return false;
    let matchedIndex = -1;
    for (let i = 0; i < user.backupCodes.length; i++) {
      const ok = await bcrypt.compare(code, user.backupCodes[i]);
      if (ok) {
        matchedIndex = i;
        break;
      }
    }
    if (matchedIndex < 0) return false;
    const next = user.backupCodes.filter((_, i) => i !== matchedIndex);
    await this.prisma.updateBackupCodes(user.id, next);
    return true;
  }

  async confirm2FA(userId: string, backupCodes: string[]) {
    await this.prisma.confirm2FA(userId, backupCodes);
  }

  async cancel2FA(userId: string) {
    await this.prisma.cancel2FA(userId);
  }

  async updatePassword(userId: string, passwordHash: string) {
    await this.prisma.updateUserPassword(userId, passwordHash);
  }
}
