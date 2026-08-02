import {
  IsString,
  IsOptional,
  IsArray,
  IsUrl,
  ArrayMinSize,
  MinLength,
  MaxLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateAppDto {
  @ApiProperty()
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  name!: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  description?: string;

  @ApiProperty({ isArray: true })
  @IsArray()
  @ArrayMinSize(1)
  @IsUrl({}, { each: true })
  redirectUris!: string[];

  @ApiProperty({ isArray: true })
  @IsArray()
  scopes!: string[];
}
