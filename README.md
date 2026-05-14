<h1 align="center">nest-auth-hybrid</h1>

<p align="center">
  API de autenticación lista para producción construida con NestJS — sesiones JWT, 2FA, OAuth y auditoría completa.
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
  <img src="https://img.shields.io/badge/OWASP_Top_10-auditado-4CAF50?style=flat-square" />
  <img src="https://img.shields.io/badge/Licencia-MIT-yellow?style=flat-square" />
</p>

<p align="center">
  <a href="./README.en.md">🇬🇧 English version</a>
</p>

---

## Descripción general

`nest-auth-hybrid` es un backend de autenticación completo que cubre cada flujo crítico que una aplicación moderna necesita — desde el login clásico con email y contraseña hasta autenticación de dos factores y SSO social — con una postura de seguridad de nivel producción validada contra el OWASP Top 10.

Se combina con [`next-auth-hybrid`](https://github.com/KamerrEzz/next-auth-hybrid) como sistema de autenticación full-stack.

---

## Funcionalidades

### Flujos de autenticación
- **Auth local** — email + contraseña con bcrypt (rondas configurables)
- **JWT** — tokens de acceso de corta duración (HS256, algoritmo fijado explícitamente) + rotación de refresh tokens con denylist
- **Sesiones** — sesiones respaldadas por Redis con expiración deslizante, soporte multi-dispositivo y revocación individual o masiva
- **Guard híbrido** — acepta transparentemente JWT en cabecera o cookie de sesión en cada endpoint protegido

### Autenticación de dos factores (2FA)
- **TOTP** — compatible con Google Authenticator (speakeasy + QR via qrcode); secreto cifrado en reposo con AES-256-GCM
- **OTP por email** — códigos de un solo uso con tiempo límite enviados vía Resend
- **Códigos de respaldo** — 10 códigos de un solo uso generados con CSPRNG, almacenados como hashes bcrypt
- **Activación/desactivación segura** — requiere el TOTP actual para rotar el secreto; flujo de cancelación para configuraciones pendientes

### Login social
- **Google OAuth 2.0** y **Discord OAuth 2.0** vía Passport
- Las cuentas creadas por SSO reciben una contraseña aleatoria criptográficamente segura para impedir el login local

### Seguridad
- Lista de orígenes permitidos en CORS con `credentials: true`
- Helmet (cabeceras de seguridad HTTP)
- Patrón de doble envío CSRF (cookie + cabecera)
- Limitación de tasa por IP y por endpoint vía Redis
- `trust proxy` configurado para obtener la IP real del cliente detrás de load balancers
- `SameSite: lax` en cookies de callbacks OAuth; `strict` en el resto
- **AuditLog** completo persistido en Postgres para cada evento de seguridad (intentos de login, cambios de contraseña, activación/desactivación de 2FA, revocación de sesiones)
- **Bloqueo de cuenta por email** — tras 5 intentos fallidos consecutivos, la cuenta queda bloqueada 15 minutos en Redis

### Infraestructura
- Conexión Redis compartida mediante `@Global() RedisModule` — sin conexiones por servicio
- Docker Compose sin credenciales hardcodeadas, puertos de datos no expuestos al host, Redis con contraseña
- Migraciones Prisma incluidas

---

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| Framework | NestJS 11 |
| Lenguaje | TypeScript 5 |
| ORM | Prisma 6 + PostgreSQL 16 |
| Caché / Sesiones | ioredis + Redis 7 |
| Auth | Passport.js, @nestjs/jwt, bcrypt |
| 2FA | speakeasy (TOTP), qrcode |
| Email | Resend |
| Validación | class-validator + class-transformer |
| Seguridad | helmet, CSRF guard, rate-limit guard personalizado |
| Contenedores | Docker + Docker Compose |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                   Petición HTTP                      │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │   HybridAuthGuard  │  JWT en cabecera O cookie de sesión
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
     │  (negocio)  │    │  (HS256 JWT)    │
     └──────┬──────┘    └─────────────────┘
            │
     ┌──────▼──────────────────────────────┐
     │           Redis (compartido)        │
     │  sesiones · tickets OTP · revocados │
     │  refresh tokens · claves rate-limit │
     └─────────────────────────────────────┘
            │
     ┌──────▼──────┐    ┌────────────────┐
     │  PostgreSQL  │    │  AuditLog DB   │
     │  Modelo User │    │  cada evento   │
     └─────────────┘    └────────────────┘
```

---

## Inicio rápido

### Requisitos previos
- Node.js >= 20
- Docker + Docker Compose

### 1. Clonar e instalar

```bash
git clone https://github.com/KamerrEzz/nest-auth-hybrid.git
cd nest-auth-hybrid
npm install
```

### 2. Configurar el entorno

```bash
cp .env.example .env
```

Variables requeridas:

```env
# Base de datos
DATABASE_URL=postgresql://user:pass@localhost:5432/authdb
POSTGRES_USER=user
POSTGRES_PASSWORD=pass
POSTGRES_DB=authdb

# Redis
REDIS_URL=redis://:password@localhost:6379
REDIS_PASSWORD=password

# JWT
JWT_SECRET=tu-secreto-de-256-bits
JWT_REFRESH_SECRET=tu-secreto-refresh-de-256-bits

# Cifrado TOTP (64 caracteres hex = 32 bytes)
TOTP_ENC_KEY=tus-64-caracteres-hex

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

### 3. Ejecutar con Docker

```bash
docker compose up --build
```

### 4. Ejecutar en local (desarrollo)

```bash
# Iniciar postgres + redis
docker compose up postgres redis -d

# Aplicar migraciones
npx prisma migrate deploy

# Iniciar la API
npm run start:dev
```

---

## Endpoints de la API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/auth/register` | Crear cuenta |
| `POST` | `/auth/login` | Login con email + contraseña |
| `POST` | `/auth/verify-otp` | Completar desafío 2FA |
| `POST` | `/auth/refresh` | Rotar refresh token |
| `GET` | `/auth/me` | Perfil del usuario actual |
| `POST` | `/auth/logout` | Invalidar sesión |
| `GET` | `/auth/csrf` | Obtener token CSRF |
| `POST` | `/auth/change-password` | Cambiar contraseña (requiere CSRF + TOTP si 2FA activo) |
| `POST` | `/auth/enable-2fa` | Iniciar configuración TOTP |
| `POST` | `/auth/verify-2fa` | Confirmar TOTP + generar códigos de respaldo |
| `POST` | `/auth/disable-2fa` | Eliminar 2FA (requiere TOTP o código de respaldo) |
| `GET` | `/auth/sessions` | Listar sesiones activas |
| `DELETE` | `/auth/sessions/others` | Revocar todas las otras sesiones |
| `DELETE` | `/auth/sessions/:id` | Revocar sesión específica |
| `GET` | `/auth/google` | Iniciar OAuth con Google |
| `GET` | `/auth/discord` | Iniciar OAuth con Discord |
| `GET` | `/notes` | Listar notas (cabecera `X-TOTP-Code` requerida para notas seguras) |
| `POST` | `/notes` | Crear nota |
| `GET` | `/notes/:id` | Obtener nota |

Documentación completa: [`auth_endpoints.md`](./auth_endpoints.md)

---

## Postura de seguridad

Este proyecto ha sido auditado contra el **OWASP Top 10 (2021)** a lo largo de cuatro sprints. Decisiones clave:

| Área | Decisión |
|---|---|
| Confusión de algoritmo | `algorithms: ['HS256']` fijado en cada verificación JWT |
| Almacenamiento de tokens | Cookies httpOnly + Secure + SameSite; sin localStorage |
| Almacenamiento de secretos | Secretos TOTP cifrados con AES-256-GCM antes de escribir en DB |
| Códigos de respaldo | CSPRNG (`randomBytes`), almacenados con hash bcrypt en DB |
| Revocación de sesiones | Denylist Redis para refresh tokens; revocación individual con verificación de propiedad |
| CSRF | Patrón de doble envío cookie/cabecera en endpoints mutables |
| Limitación de tasa | Por-IP + por-ruta via Redis; Throttler global en todas las rutas |
| Bloqueo de cuenta | 5 intentos fallidos → bloqueo de 15 min en Redis (por email, independiente del rate limit por IP) |
| Rastro de auditoría | Cada evento de autenticación persistido en tabla `AuditLog` de Postgres |
| Infraestructura | Sin credenciales en compose; puertos de datos internos; Redis con `requirepass` |

---

## Licencia

MIT © [Kamerr Ezz](https://github.com/KamerrEzz)
