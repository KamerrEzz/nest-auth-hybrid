import { Injectable, UnauthorizedException } from '@nestjs/common';
import { NoteService } from '../../modules/note/note.service';
import { UserService } from '../../modules/user/user.service';
import { TotpService } from '../../modules/totp/totp.service';
import { Module } from '@nestjs/common';

@Injectable()
export class NotesService {
  constructor(
    private notes: NoteService,
    private users: UserService,
    private totp: TotpService,
  ) {}

  async create(
    userId: string,
    data: { title: string; content: string; secure?: boolean },
  ) {
    return this.notes.create(userId, data);
  }

  async list(userId: string, totpCode?: string) {
    const all = await this.notes.listByUser(userId);
    const user = await this.users.findById(userId);
    const needsTotp = !!user?.has2FA;
    if (!needsTotp) return all;
    if (totpCode && user?.totpSecret) {
      const secret = this.totp.decryptSecret(user.totpSecret);
      const ok = this.totp.verify(totpCode, secret);
      if (ok) return all;
    }
    return all.filter((n) => !n.secure);
  }

  async get(userId: string, id: string, totpCode?: string) {
    const note = await this.notes.get(id);
    if (!note || note.userId !== userId) throw new UnauthorizedException();
    if (!note.secure) return note;
    const user = await this.users.findById(userId);
    if (user?.has2FA && user.totpSecret) {
      const secret = this.totp.decryptSecret(user.totpSecret);
      const ok = totpCode ? this.totp.verify(totpCode, secret) : false;
      if (!ok) throw new UnauthorizedException();
    }
    return note;
  }
}

@Module({
  providers: [NotesService],
  exports: [NotesService],
})
export class NotesFeatureModule {}
