import { IsOptional, IsString } from 'class-validator';

export class ListNotesQueryDto {
  @IsOptional()
  @IsString()
  totpCode?: string;
}

export class GetNoteQueryDto {
  @IsOptional()
  @IsString()
  totpCode?: string;
}
