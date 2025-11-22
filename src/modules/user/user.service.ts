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

  async enable2FA(
    userId: string,
    totpSecretEnc: string,
    backupCodes: string[],
  ) {
    await this.prisma.enable2FA(userId, totpSecretEnc, backupCodes);
  }

  async disable2FA(userId: string) {
    await this.prisma.disable2FA(userId);
  }
}
