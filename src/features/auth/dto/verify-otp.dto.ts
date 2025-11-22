import { IsOptional, IsString } from 'class-validator';

export class VerifyOtpDto {
  @IsString()
  tempToken!: string;

  @IsString()
  otpCode!: string;

  @IsOptional()
  @IsString()
  totpCode?: string;
}
