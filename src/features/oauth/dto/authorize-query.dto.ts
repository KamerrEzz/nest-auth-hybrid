import { IsString, IsOptional, IsIn } from 'class-validator';

export class AuthorizeQueryDto {
  @IsString()
  @IsIn(['code'])
  response_type!: string;

  @IsString()
  client_id!: string;

  @IsString()
  redirect_uri!: string;

  @IsOptional()
  @IsString()
  scope?: string;

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  code_challenge?: string;

  @IsOptional()
  @IsString()
  @IsIn(['S256', 'plain'])
  code_challenge_method?: string;
}
