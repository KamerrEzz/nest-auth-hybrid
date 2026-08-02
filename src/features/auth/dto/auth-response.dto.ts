import { Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { UserResponseDto } from '../../../modules/user/dto/user-response.dto';

export class AuthResponseDto {
  @ApiProperty()
  @Expose()
  accessToken!: string;

  @ApiProperty()
  @Expose()
  refreshToken!: string;

  @ApiProperty()
  @Expose()
  user!: UserResponseDto;

  @ApiProperty()
  @Expose()
  expiresIn!: number;

  constructor(partial: Partial<AuthResponseDto>) {
    Object.assign(this, partial);
  }
}
