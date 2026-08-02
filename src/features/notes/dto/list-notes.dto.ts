import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ListNotesQueryDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  totpCode?: string;
}

export class GetNoteQueryDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  totpCode?: string;
}
