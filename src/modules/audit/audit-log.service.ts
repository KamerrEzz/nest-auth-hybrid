import { Injectable } from '@nestjs/common';
import { PrismaRepository } from '../database/prisma/prisma.service';

export interface AuditLogEvent {
  userId?: string;
  action: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  severity: 'info' | 'warning' | 'critical';
}

@Injectable()
export class AuditLogService {
  constructor(private prisma: PrismaRepository) {}

  async log(event: AuditLogEvent): Promise<void> {
    try {
      await this.prisma.createAuditLog({
        userId: event.userId,
        action: event.action,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: event.metadata,
        severity: event.severity,
      });
    } catch {
      // Non-fatal: never let audit failure break the primary request
    }
  }

  async logFailedLogin(
    email: string,
    reason: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      action: 'LOGIN_FAILED',
      metadata: { email, reason },
      ipAddress,
      userAgent,
      severity: 'warning',
    });
  }

  async logSuccessfulLogin(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: 'LOGIN_SUCCESS',
      ipAddress,
      userAgent,
      severity: 'info',
    });
  }

  async logPasswordChange(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: 'PASSWORD_CHANGED',
      ipAddress,
      userAgent,
      severity: 'info',
    });
  }

  async log2FAEnabled(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: '2FA_ENABLED',
      ipAddress,
      userAgent,
      severity: 'info',
    });
  }

  async log2FADisabled(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: '2FA_DISABLED',
      ipAddress,
      userAgent,
      severity: 'warning',
    });
  }

  async logBackupCodeUsed(
    userId: string,
    remainingCodes: number,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: 'BACKUP_CODE_USED',
      metadata: { remainingCodes },
      ipAddress,
      userAgent,
      severity: remainingCodes <= 2 ? 'warning' : 'info',
    });
  }

  async logSessionRevoked(
    userId: string,
    sessionId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: 'SESSION_REVOKED',
      metadata: { sessionId },
      ipAddress,
      userAgent,
      severity: 'info',
    });
  }
}
