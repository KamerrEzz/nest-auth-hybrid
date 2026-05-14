import {
  IsString,
  IsOptional,
  IsArray,
  IsUrl,
  ArrayMinSize,
  MinLength,
  MaxLength,
} from 'class-validator';

export class CreateAppDto {
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  name!: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  description?: string;

  @IsArray()
  @ArrayMinSize(1)
  @IsUrl({}, { each: true })
  redirectUris!: string[];

  @IsArray()
  scopes!: string[];
}
