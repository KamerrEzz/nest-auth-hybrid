import { Injectable } from '@nestjs/common';
import { PrismaRepository } from '../database/prisma/prisma.service';

export interface AuditLogEvent {
  userId?: string;
  action: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  severity: 'info' | 'warning' | 'critical';
}

@Injectable()
export class AuditLogService {
  constructor(private prisma: PrismaRepository) {}

  /**
   * Registra un evento de auditoría
   * @param event - Evento a registrar
   */
  async log(event: AuditLogEvent): Promise<void> {
    try {
      // TODO: Implementar cuando el modelo AuditLog esté en Prisma
      // await this.prisma.auditLog.create({
      //   data: {
      //     userId: event.userId,
      //     action: event.action,
      //     ipAddress: event.ipAddress,
      //     userAgent: event.userAgent,
      //     metadata: event.metadata,
      //     severity: event.severity,
      //     timestamp: new Date(),
      //   },
      // });

      // Por ahora, solo logear en consola
      console.log('[AUDIT]', {
        timestamp: new Date().toISOString(),
        ...event,
      });
    } catch (error) {
      // No fallar si el logging falla
      console.error('[AUDIT ERROR]', error);
    }
  }

  /**
   * Registra un intento de login fallido
   */
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

  /**
   * Registra un login exitoso
   */
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

  /**
   * Registra un cambio de contraseña
   */
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

  /**
   * Registra habilitación de 2FA
   */
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

  /**
   * Registra deshabilitación de 2FA
   */
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

  /**
   * Registra uso de código de respaldo
   */
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

  /**
   * Registra revocación de sesión
   */
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
