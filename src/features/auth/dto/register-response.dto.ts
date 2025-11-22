import { Expose } from 'class-transformer';
import { UserResponseDto } from '../../../modules/user/dto/user-response.dto';

export class RegisterResponseDto {
  @Expose()
  message!: string;

  @Expose()
  user!: UserResponseDto;

  @Expose()
  accessToken!: string;

  @Expose()
  refreshToken!: string;

  constructor(partial: Partial<RegisterResponseDto>) {
    Object.assign(this, partial);
  }
}
