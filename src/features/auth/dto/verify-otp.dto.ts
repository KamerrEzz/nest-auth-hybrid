import { IsOptional, IsString } from 'class-validator';

export class VerifyOtpDto {
  @IsString()
  tempToken!: string;

  @IsOptional()
  @IsString()
  otpCode?: string;

  @IsOptional()
  @IsString()
  totpCode?: string;
}
