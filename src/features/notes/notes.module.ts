import { Module } from '@nestjs/common';
import { NotesController } from './notes.controller';
import { NotesService } from './notes.service';
import { NoteModule } from '../../modules/note/note.module';
import { UserModule } from '../../modules/user/user.module';
import { TotpModule } from '../../modules/totp/totp.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [NoteModule, UserModule, TotpModule, AuthModule],
  controllers: [NotesController],
  providers: [NotesService],
})
export class NotesModule {}
