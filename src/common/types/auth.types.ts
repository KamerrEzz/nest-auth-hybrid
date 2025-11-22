export interface UserEntity {
  id: string;
  email: string;
  password: string;
  name?: string | null;
  has2FA: boolean;
}
