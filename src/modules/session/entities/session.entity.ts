export interface SessionEntity {
  id: string;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  location?: string;
  expiresAt: number;
  lastActive: number;
}
