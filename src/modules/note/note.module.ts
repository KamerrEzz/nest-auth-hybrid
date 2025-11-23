import { Module } from '@nestjs/common';
import { NoteService } from './note.service';

@Module({
  providers: [NoteService],
  exports: [NoteService],
})
export class NoteModule {}
