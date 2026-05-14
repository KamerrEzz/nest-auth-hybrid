<h1 align="center">nest-auth-hybrid</h1>

<p align="center">
  Production-ready authentication API built with NestJS — JWT sessions, 2FA, OAuth and full audit trail.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/NestJS-11-E0234E?style=flat-square&logo=nestjs&logoColor=white" />
  <img src="https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Prisma-6-2D3748?style=flat-square&logo=prisma&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OWASP_Top_10-audited-4CAF50?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
</p>

---

## Overview

`nest-auth-hybrid` is a fully-featured authentication backend that covers every critical flow a modern application needs — from standard email/password login to hardware-based two-factor authentication and social SSO — with a production-grade security posture validated against the OWASP Top 10.

It pairs with [`next-auth-hybrid`](https://github.com/KamerrEzz/next-auth-hybrid) as a full-stack authentication system.

---

## Features

### Authentication flows
- **Local auth** — email + password with bcrypt (configurable rounds)
- **JWT** — short-lived access tokens (HS256, explicit algorithm pinning) + refresh token rotation with denylist
- **Session** — Redis-backed sessions with sliding expiry, multi-device support and individual/bulk revocation
- **Hybrid guard** — transparently accepts either JWT header or session cookie on every protected endpoint

### Two-Factor Authentication
- **TOTP** — Google Authenticator compatible (speakeasy + QR via qrcode); secret encrypted at rest with AES-256-GCM
- **Email OTP** — time-limited one-time codes sent via Resend
- **Backup codes** — 10 single-use codes generated with CSPRNG, stored as bcrypt hashes
- **Graceful enable/disable** — requires current TOTP to rotate the shared secret; cancel flow for pending setup

### Social login
- **Google OAuth 2.0** and **Discord OAuth 2.0** via Passport
- Accounts created with a cryptographically random placeholder password so local login is not possible on SSO-only accounts

### Security
- CORS allowlist with `credentials: true`
- Helmet (HTTP security headers)
- CSRF cookie/header double-submit pattern
- IP-based rate limiting per endpoint via Redis
- `trust proxy` set for correct client IP behind load balancers
- `SameSite: lax` on OAuth callback cookies; `strict` on all other auth cookies
- Full **AuditLog** persisted to Postgres for every security event (login attempts, password changes, 2FA enable/disable, session revocations)

### Infrastructure
- Single shared Redis connection via `@Global() RedisModule` — no per-service connections
- Docker Compose with no hardcoded credentials, data ports not exposed to host, Redis password-protected
- Prisma migrations included

---

## Stack

| Layer | Technology |
|---|---|
| Framework | NestJS 11 |
| Language | TypeScript 5 |
| ORM | Prisma 6 + PostgreSQL 16 |
| Cache / Sessions | ioredis + Redis 7 |
| Auth | Passport.js, @nestjs/jwt, bcrypt |
| 2FA | speakeasy (TOTP), qrcode |
| Email | Resend |
| Validation | class-validator + class-transformer |
| Security | helmet, CSRF guard, custom rate-limit guard |
| Containerisation | Docker + Docker Compose |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    HTTP Request                      │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │   HybridAuthGuard  │  JWT header OR session cookie
              └─────────┬──────────┘
                        │
         ┌──────────────▼──────────────┐
         │        AuthController       │
         │  /login  /register  /me     │
         │  /enable-2fa  /verify-2fa   │
         │  /sessions  /refresh        │
         └──────┬──────────────┬───────┘
                │              │
     ┌──────────▼──┐    ┌──────▼──────────┐
     │ AuthService │    │  TokenService   │
     │  (business) │    │  (HS256 JWT)    │
     └──────┬──────┘    └─────────────────┘
            │
     ┌──────▼──────────────────────────────┐
     │           Redis (shared)            │
     │  sessions · OTP tickets · revoked   │
     │  refresh tokens · rate-limit keys   │
     └─────────────────────────────────────┘
            │
     ┌──────▼──────┐    ┌────────────────┐
     │  PostgreSQL  │    │  AuditLog DB   │
     │  User model  │    │  every event   │
     └─────────────┘    └────────────────┘
```

---

## Quick Start

### Prerequisites
- Node.js >= 20
- Docker + Docker Compose

### 1. Clone and install

```bash
git clone https://github.com/KamerrEzz/nest-auth-hybrid.git
cd nest-auth-hybrid
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Required variables:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/authdb
POSTGRES_USER=user
POSTGRES_PASSWORD=pass
POSTGRES_DB=authdb

# Redis
REDIS_URL=redis://:password@localhost:6379
REDIS_PASSWORD=password

# JWT
JWT_SECRET=your-256-bit-secret
JWT_REFRESH_SECRET=your-256-bit-refresh-secret

# TOTP encryption (64 hex chars = 32 bytes)
TOTP_ENC_KEY=your-64-hex-chars

# OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=
DISCORD_CALLBACK_URL=http://localhost:3000/auth/discord/callback

# Email (Resend)
RESEND_API_KEY=

# App
APP_URL=http://localhost:3001
NODE_ENV=development
PORT=3000
```

### 3. Run with Docker

```bash
docker compose up --build
```

### 4. Run locally (dev)

```bash
# Start postgres + redis
docker compose up postgres redis -d

# Apply migrations
npx prisma migrate deploy

# Start API
npm run start:dev
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create account |
| `POST` | `/auth/login` | Email + password login |
| `POST` | `/auth/verify-otp` | Complete 2FA challenge |
| `POST` | `/auth/refresh` | Rotate refresh token |
| `GET` | `/auth/me` | Current user profile |
| `POST` | `/auth/logout` | Invalidate session |
| `GET` | `/auth/csrf` | Obtain CSRF token |
| `POST` | `/auth/change-password` | Change password (requires CSRF + TOTP if 2FA active) |
| `POST` | `/auth/enable-2fa` | Begin TOTP setup |
| `POST` | `/auth/verify-2fa` | Confirm TOTP + generate backup codes |
| `POST` | `/auth/disable-2fa` | Remove 2FA (requires TOTP or backup code) |
| `GET` | `/auth/sessions` | List active sessions |
| `DELETE` | `/auth/sessions/others` | Revoke all other sessions |
| `DELETE` | `/auth/sessions/:id` | Revoke specific session |
| `GET` | `/auth/google` | Initiate Google OAuth |
| `GET` | `/auth/discord` | Initiate Discord OAuth |
| `GET` | `/notes` | List notes (`X-TOTP-Code` header required for secure notes) |
| `POST` | `/notes` | Create note |
| `GET` | `/notes/:id` | Get note |

Full documentation: [`auth_endpoints.md`](./auth_endpoints.md)

---

## Security Posture

This project has been audited against the **OWASP Top 10 (2021)** across three sprints. Key decisions:

| Area | Decision |
|---|---|
| Algorithm confusion | `algorithms: ['HS256']` pinned on every JWT verify |
| Token storage | httpOnly + Secure + SameSite cookies; no localStorage |
| Secret storage | TOTP secrets encrypted AES-256-GCM before DB write |
| Backup codes | CSPRNG (`randomBytes`), bcrypt-hashed in DB |
| Session revocation | Redis denylist for refresh tokens; individual session revoke with ownership check |
| CSRF | Double-submit cookie/header pattern on mutating endpoints |
| Rate limiting | Per-IP + per-path via Redis; global Throttler on all routes |
| Audit trail | Every auth event persisted to `AuditLog` Postgres table |
| Infrastructure | No credentials in compose; data ports internal-only; Redis `requirepass` |

---

## License

MIT © [Kamerr Ezz](https://github.com/KamerrEzz)
