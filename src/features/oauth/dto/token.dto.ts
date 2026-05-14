import { IsString, IsOptional, IsIn } from 'class-validator';

export class TokenDto {
  @IsString()
  @IsIn(['authorization_code', 'refresh_token'])
  grant_type!: string;

  @IsOptional()
  @IsString()
  code?: string;

  @IsOptional()
  @IsString()
  redirect_uri?: string;

  @IsString()
  client_id!: string;

  @IsOptional()
  @IsString()
  client_secret?: string;

  @IsOptional()
  @IsString()
  code_verifier?: string;

  @IsOptional()
  @IsString()
  refresh_token?: string;
}
