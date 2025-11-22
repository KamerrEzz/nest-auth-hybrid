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

  async sendOtp(to: string, code: string) {
    if (!this.resend) return;
    try {
      await this.resend.emails.send({
        from: this.from,
        to,
        subject: 'Tu código OTP',
        text: `Código: ${code}`,
      });
    } catch {
      return;
    }
  }
}
