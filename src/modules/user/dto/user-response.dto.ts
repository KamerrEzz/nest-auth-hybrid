import { Exclude, Expose } from 'class-transformer';

export class UserResponseDto {
  @Expose()
  id!: string;

  @Expose()
  email!: string;

  @Expose()
  name?: string;

  @Expose()
  createdAt!: Date;

  @Exclude()
  password!: string;

  @Exclude()
  totpSecret!: string | null;

  @Exclude()
  backupCodes!: string[];

  @Exclude()
  has2FA!: boolean;

  @Exclude()
  updatedAt!: Date;

  @Exclude()
  lastLoginAt!: Date;

  constructor(partial: Partial<UserResponseDto>) {
    Object.assign(this, partial);
  }
}
