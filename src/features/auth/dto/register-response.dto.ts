import { Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { UserResponseDto } from '../../../modules/user/dto/user-response.dto';

export class RegisterResponseDto {
  @ApiProperty()
  @Expose()
  message!: string;

  @ApiProperty()
  @Expose()
  user!: UserResponseDto;

  @ApiProperty()
  @Expose()
  accessToken!: string;

  @ApiProperty()
  @Expose()
  refreshToken!: string;

  constructor(partial: Partial<RegisterResponseDto>) {
    Object.assign(this, partial);
  }
}
