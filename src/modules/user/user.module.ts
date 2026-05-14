import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { AuditModule } from '../audit/audit.module';
import { EmailModule } from '../email/email.module';

@Module({
  imports: [AuditModule, EmailModule],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
