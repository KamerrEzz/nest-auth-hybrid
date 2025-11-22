export interface UserEntity {
  id: string;
  email: string;
  password: string;
  name?: string | null;
  has2FA: boolean;
  totpSecret?: string | null;
  backupCodes?: string[];
}
