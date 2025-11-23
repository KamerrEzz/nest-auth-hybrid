import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import appConfig from './config/app.config';
import jwtConfig from './config/jwt.config';
import sessionConfig from './config/session.config';
import cacheConfig from './config/cache.config';
import securityConfig from './config/security.config';
import { ThrottlerModule } from '@nestjs/throttler';
import { PrismaModule } from './modules/database/prisma/prisma.module';
import { UserModule } from './modules/user/user.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './features/auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { CsrfGuard } from './common/guards/csrf.guard';
import { PassportModule } from '@nestjs/passport';
import { NoteModule } from './modules/note/note.module';
import { NotesModule } from './features/notes/notes.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig, jwtConfig, sessionConfig, cacheConfig, securityConfig],
    }),
    ThrottlerModule.forRoot([
      {
        ttl: securityConfig().rateLimitTtl,
        limit: securityConfig().rateLimitMax,
      },
    ]),
    PrismaModule,
    PassportModule,
    UserModule,
    AuthModule,
    NoteModule,
    NotesModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
  ],
})
export class AppModule {}
