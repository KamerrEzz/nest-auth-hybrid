declare module 'speakeasy' {
  export interface GeneratedSecret {
    ascii?: string;
    hex?: string;
    base32: string;
    otpauth_url?: string;
  }
  export function generateSecret(options: {
    length?: number;
    name?: string;
  }): GeneratedSecret;
  export const totp: {
    verify(options: {
      secret: string;
      encoding: 'base32';
      window?: number;
      step?: number;
      token: string;
    }): boolean;
  };
}
