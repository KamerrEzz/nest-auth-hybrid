import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

@Injectable()
export class TotpService {
  constructor(private config: ConfigService) {}

  generateSecret(label: string) {
    const secret = speakeasy.generateSecret({ length: 20, name: label });
    return { base32: secret.base32, otpauthUrl: secret.otpauth_url! };
  }

  async generateQrDataUrl(otpauthUrl: string) {
    return await qrcode.toDataURL(otpauthUrl);
  }

  verify(code: string, secretBase32: string) {
    return speakeasy.totp.verify({
      secret: secretBase32,
      encoding: 'base32',
      window: 1,
      step: 30,
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
      throw new Error('Missing security.totpEncKey');
    }
    return Buffer.from(raw.slice(0, 32));
  }
}
