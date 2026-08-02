import { IsString, IsOptional, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TokenDto {
  @ApiProperty()
  @IsString()
  @IsIn(['authorization_code', 'refresh_token'])
  grant_type!: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  redirect_uri?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  client_id?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  client_secret?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  code_verifier?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  refresh_token?: string;
}
