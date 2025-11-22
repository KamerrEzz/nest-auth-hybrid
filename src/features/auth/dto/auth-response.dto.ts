import { Expose } from 'class-transformer';
import { UserResponseDto } from '../../../modules/user/dto/user-response.dto';

export class AuthResponseDto {
  @Expose()
  accessToken!: string;

  @Expose()
  refreshToken!: string;

  @Expose()
  user!: UserResponseDto;

  @Expose()
  expiresIn!: number;

  constructor(partial: Partial<AuthResponseDto>) {
    Object.assign(this, partial);
  }
}
