import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiTags,
} from '@nestjs/swagger';
import { HybridAuthGuard } from '../../common/guards/hybrid-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { NotesService } from './notes.service';
import { CreateNoteDto } from './dto/create-note.dto';
import type { NoteEntity } from '../../modules/note/entities/note.entity';

@ApiTags('notes')
@Controller('notes')
export class NotesController {
  constructor(private readonly notes: NotesService) {}

  @Post()
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'Create a new note' })
  @ApiResponse({ status: 201, description: 'Note created' })
  @ApiBearerAuth('JWT')
  create(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateNoteDto,
  ): Promise<NoteEntity> {
    return this.notes.create(user.id, dto);
  }

  @Get()
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'List all notes for the current user' })
  @ApiResponse({ status: 200, description: 'Notes listed' })
  @ApiBearerAuth('JWT')
  list(
    @CurrentUser() user: { id: string },
    @Headers('x-totp-code') totpCode?: string,
  ): Promise<NoteEntity[]> {
    return this.notes.list(user.id, totpCode);
  }

  @Get(':id')
  @UseGuards(HybridAuthGuard)
  @ApiOperation({ summary: 'Get a specific note by ID' })
  @ApiResponse({ status: 200, description: 'Note retrieved' })
  @ApiBearerAuth('JWT')
  get(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Headers('x-totp-code') totpCode?: string,
  ): Promise<NoteEntity> {
    return this.notes.get(user.id, id, totpCode);
  }
}
