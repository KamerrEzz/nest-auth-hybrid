import { IsString, IsOptional, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AuthorizeQueryDto {
  @ApiProperty()
  @IsString()
  @IsIn(['code'])
  response_type!: string;

  @ApiProperty()
  @IsString()
  client_id!: string;

  @ApiProperty()
  @IsString()
  redirect_uri!: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  scope?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  state?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  code_challenge?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @IsIn(['S256', 'plain'])
  code_challenge_method?: string;
}
