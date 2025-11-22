import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

@Injectable()
export class TotpService {
  constructor(private config: ConfigService) {}

  generateSecret(label: string): { base32: string; otpauthUrl: string } {
    const gen: (opts: { length?: number; name?: string }) => {
      base32: string;
      otpauth_url?: string;
    } = (
      speakeasy as unknown as {
        generateSecret: typeof speakeasy.generateSecret;
      }
    ).generateSecret as unknown as (opts: {
      length?: number;
      name?: string;
    }) => {
      base32: string;
      otpauth_url?: string;
    };
    const secret = gen({ length: 20, name: label });
    return { base32: secret.base32, otpauthUrl: secret.otpauth_url ?? '' };
  }

  async generateQrDataUrl(otpauthUrl: string): Promise<string> {
    const toData: (s: string) => Promise<string> = (
      qrcode as unknown as {
        toDataURL: (s: string) => Promise<string>;
      }
    ).toDataURL;
    return await toData(otpauthUrl);
  }

  verify(code: string, secretBase32: string): boolean {
    const verifyFn: (opts: {
      secret: string;
      encoding: 'base32';
      window: number;
      step: number;
      token: string;
    }) => boolean = (
      speakeasy as unknown as {
        totp: {
          verify: (opts: {
            secret: string;
            encoding: 'base32';
            window: number;
            step: number;
            token: string;
          }) => boolean;
        };
      }
    ).totp.verify;
    return verifyFn({
      secret: secretBase32,
      encoding: 'base32',
      window: 1,
      step: 30,
      token: code,
    });
  }

  encryptSecret(plain: string) {
    const key = this.getKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString('base64');
  }

  decryptSecret(encB64: string) {
    const buf = Buffer.from(encB64, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const data = buf.subarray(28);
    const key = this.getKey();
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return dec.toString('utf8');
  }

  private getKey() {
    const raw = this.config.get<string>('security.totpEncKey') ?? '';
    if (!raw || raw.length < 32) {
      throw new Error('Missing TOTP_ENC_KEY');
    }
    if (/^[0-9a-fA-F]{64}$/.test(raw)) {
      return Buffer.from(raw, 'hex');
    }
    return Buffer.from(raw.slice(0, 32), 'utf8');
  }
}
