-- CreateTable
CREATE TABLE "AuditLog" (
    "id"        TEXT NOT NULL,
    "userId"    TEXT,
    "action"    TEXT NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata"  JSONB,
    "severity"  TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");
