export interface SessionEntity {
  id: string;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  expiresAt: number;
}
