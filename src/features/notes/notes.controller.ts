import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { NotesService } from './notes.service';
import { CreateNoteDto } from './dto/create-note.dto';
import type { NoteEntity } from '../../modules/note/entities/note.entity';

@Controller('notes')
export class NotesController {
  constructor(private readonly notes: NotesService) {}

  @Post()
  @UseGuards(HybridAuthGuard)
  create(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateNoteDto,
  ): Promise<NoteEntity> {
    return this.notes.create(user.id, dto);
  }

  @Get()
  @UseGuards(HybridAuthGuard)
  list(
    @CurrentUser() user: { id: string },
    @Headers('x-totp-code') totpCode?: string,
  ): Promise<NoteEntity[]> {
    return this.notes.list(user.id, totpCode);
  }

  @Get(':id')
  @UseGuards(HybridAuthGuard)
  get(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Headers('x-totp-code') totpCode?: string,
  ): Promise<NoteEntity> {
    return this.notes.get(user.id, id, totpCode);
  }
}
