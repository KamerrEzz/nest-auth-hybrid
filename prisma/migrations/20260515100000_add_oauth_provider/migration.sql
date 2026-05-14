-- AlterTable User (add relations - no columns needed, handled by relation models)

-- CreateTable OAuthApp
CREATE TABLE "OAuthApp" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecret" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "redirectUris" TEXT[],
    "scopes" TEXT[],
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "OAuthApp_pkey" PRIMARY KEY ("id")
);

-- CreateTable OAuthAuthCode
CREATE TABLE "OAuthAuthCode" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scopes" TEXT[],
    "redirectUri" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "codeChallenge" TEXT,
    "codeChallengeMethod" TEXT,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "OAuthAuthCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable OAuthToken
CREATE TABLE "OAuthToken" (
    "id" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "refreshToken" TEXT,
    "clientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "OAuthToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "OAuthApp_clientId_key" ON "OAuthApp"("clientId");
CREATE INDEX "OAuthApp_userId_idx" ON "OAuthApp"("userId");
CREATE UNIQUE INDEX "OAuthAuthCode_code_key" ON "OAuthAuthCode"("code");
CREATE INDEX "OAuthAuthCode_clientId_idx" ON "OAuthAuthCode"("clientId");
CREATE UNIQUE INDEX "OAuthToken_accessToken_key" ON "OAuthToken"("accessToken");
CREATE UNIQUE INDEX "OAuthToken_refreshToken_key" ON "OAuthToken"("refreshToken");
CREATE INDEX "OAuthToken_clientId_idx" ON "OAuthToken"("clientId");
CREATE INDEX "OAuthToken_userId_idx" ON "OAuthToken"("userId");

-- AddForeignKey
ALTER TABLE "OAuthApp" ADD CONSTRAINT "OAuthApp_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OAuthAuthCode" ADD CONSTRAINT "OAuthAuthCode_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OAuthApp"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OAuthAuthCode" ADD CONSTRAINT "OAuthAuthCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OAuthToken" ADD CONSTRAINT "OAuthToken_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OAuthApp"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OAuthToken" ADD CONSTRAINT "OAuthToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
