import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
  private resend: Resend | null;
  private from: string;

  constructor(private config: ConfigService) {
    const key = this.config.get<string>('RESEND_API_KEY');
    this.resend = key ? new Resend(key) : null;
    this.from = this.config.get<string>('FROM_EMAIL') ?? 'noreply@example.com';
  }

  private async send(to: string, subject: string, html: string, text: string) {
    if (!this.resend) return;
    try {
      await this.resend.emails.send({
        from: this.from,
        to,
        subject,
        html,
        text,
      });
    } catch {
      // Non-fatal: email failure never breaks the primary request
    }
  }

  private baseLayout(title: string, body: string) {
    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { margin: 0; padding: 0; background: #0f1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #e2e8f0; }
    .wrapper { max-width: 560px; margin: 40px auto; padding: 0 16px; }
    .card { background: #1a1d2e; border: 1px solid rgba(99,179,237,0.15); border-radius: 12px; padding: 40px; }
    .logo { font-size: 20px; font-weight: 700; color: #63b3ed; margin-bottom: 32px; }
    h1 { font-size: 22px; font-weight: 600; color: #f0f4f8; margin: 0 0 12px; }
    p { font-size: 15px; line-height: 1.6; color: #a0aec0; margin: 0 0 20px; }
    .btn { display: inline-block; background: #3b82f6; color: #fff !important; text-decoration: none; padding: 13px 28px; border-radius: 8px; font-size: 15px; font-weight: 600; margin: 8px 0 24px; }
    .code { display: inline-block; background: #0f1117; border: 1px solid rgba(99,179,237,0.25); border-radius: 8px; padding: 16px 32px; font-family: monospace; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #63b3ed; margin: 8px 0 24px; }
    .footer { margin-top: 32px; font-size: 12px; color: #4a5568; text-align: center; }
    .divider { border: none; border-top: 1px solid rgba(255,255,255,0.06); margin: 24px 0; }
    .warning { background: rgba(237,137,54,0.1); border: 1px solid rgba(237,137,54,0.25); border-radius: 8px; padding: 14px 16px; font-size: 13px; color: #ed8936; margin: 16px 0; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="logo">🔐 VaultAuth</div>
      ${body}
    </div>
    <div class="footer">© ${new Date().getFullYear()} VaultAuth · Si no solicitaste este email, ignóralo.</div>
  </div>
</body>
</html>`;
  }

  async sendOtp(to: string, code: string) {
    const html = this.baseLayout(
      'Código de verificación',
      `
      <h1>Tu código de verificación</h1>
      <p>Usa este código para completar el inicio de sesión. Expira en <strong>10 minutos</strong>.</p>
      <div class="code">${code}</div>
      <hr class="divider" />
      <p style="font-size:13px">Si no intentaste iniciar sesión, alguien podría estar intentando acceder a tu cuenta.</p>
    `,
    );
    await this.send(
      to,
      'Código de verificación — VaultAuth',
      html,
      `Tu código OTP: ${code}. Expira en 10 minutos.`,
    );
  }

  async sendPasswordReset(to: string, resetUrl: string) {
    const html = this.baseLayout(
      'Restablecer contraseña',
      `
      <h1>¿Olvidaste tu contraseña?</h1>
      <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta. Haz clic en el botón para continuar.</p>
      <a href="${resetUrl}" class="btn">Restablecer contraseña</a>
      <hr class="divider" />
      <div class="warning">⚠️ Este enlace expira en <strong>1 hora</strong>. Si no solicitaste el restablecimiento, puedes ignorar este mensaje.</div>
      <p style="font-size:12px;word-break:break-all;color:#4a5568">O copia este enlace: ${resetUrl}</p>
    `,
    );
    await this.send(
      to,
      'Restablecer contraseña — VaultAuth',
      html,
      `Restablece tu contraseña: ${resetUrl}\n\nEste enlace expira en 1 hora.`,
    );
  }

  async sendEmailVerification(to: string, verificationUrl: string) {
    const html = this.baseLayout(
      'Verifica tu email',
      `
      <h1>Verifica tu dirección de email</h1>
      <p>Gracias por registrarte en VaultAuth. Haz clic en el botón para verificar tu cuenta.</p>
      <a href="${verificationUrl}" class="btn">Verificar email</a>
      <hr class="divider" />
      <p style="font-size:13px">Este enlace expira en <strong>24 horas</strong>.</p>
    `,
    );
    await this.send(
      to,
      'Verifica tu email — VaultAuth',
      html,
      `Verifica tu email: ${verificationUrl}`,
    );
  }

  async sendLowBackupCodesWarning(to: string, remaining: number) {
    const html = this.baseLayout(
      'Backup codes bajos',
      `
      <h1>Te quedan pocos backup codes</h1>
      <div class="warning">⚠️ Solo te quedan <strong>${remaining} backup code${remaining === 1 ? '' : 's'}</strong> de autenticación de dos factores.</div>
      <p>Si los pierdes todos sin tener acceso a tu app autenticadora, podrías perder acceso a tu cuenta.</p>
      <p>Accede a tu cuenta y genera nuevos backup codes desde la sección de seguridad.</p>
    `,
    );
    await this.send(
      to,
      'Pocos backup codes restantes — VaultAuth',
      html,
      `Te quedan ${remaining} backup codes de 2FA. Genera nuevos desde tu cuenta.`,
    );
  }
}
