# Changelog

Todas las novedades relevantes de este proyecto se documentan aquí. El
formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto adopta [Versionado Semántico](https://semver.org/lang/es/).

## [0.2.1] - 2026-05-14

### Sprint 7 — Correcciones de compatibilidad OAuth

#### Added

- **`client_secret_basic` en el endpoint `/oauth/token`**: el handler ahora
  extrae `client_id` y `client_secret` del encabezado `Authorization: Basic`
  cuando no vienen en el cuerpo. Auth.js / NextAuth v5 usa este método por
  defecto, conforme al RFC 6749 § 2.3.1. El descubrimiento OIDC anuncia
  `client_secret_post`, `client_secret_basic` y `none` como métodos soportados.

#### Changed

- **`TokenDto.client_id` y `client_secret` marcados como `@IsOptional()`**:
  class-validator ya no rechaza la petición cuando las credenciales viajan en
  la cabecera `Authorization: Basic` en lugar del body.

#### Fixed

- **JWT `alg` HS256 rechazado por `oauth4webapi`**: el endpoint `/oauth/token`
  incluía un `id_token` firmado con HS256 cuando el scope `openid` estaba
  presente. `oauth4webapi` (usado internamente por Auth.js / NextAuth v5)
  espera RS256 por defecto para `id_token` conforme a la especificación OIDC
  Core. Solución: se elimina `id_token` de la respuesta del token endpoint; los
  clientes obtienen los claims del usuario mediante el endpoint estándar
  `/oauth/userinfo`.
- **Sesiones obsoletas causaban violación de FK**: si un usuario eliminaba y
  recreaba su cuenta (p. ej. volviendo a ejecutar `prisma db seed`), una cookie
  `sessionId` antigua apuntaba a un `userId` ya inexistente. `SessionAuthGuard`
  ahora verifica que el usuario existe en la base de datos y lanza 401 si no,
  evitando el error `OAuthAuthCode_userId_fkey` en cascada.

---

## [0.2.0] - 2026-05-14

### Sprint 6 — OAuth 2.0 Authorization Server

#### Added

- **VaultAuth como proveedor OAuth 2.0 / OIDC**: el backend expone ahora un
  Authorization Server completo, compatible con el flujo `authorization_code`
  (con PKCE opcional para clientes públicos) y `refresh_token`. Aplicaciones
  de terceros pueden delegar la autenticación en VaultAuth igual que harían
  con Google o Discord.
- **Endpoints OAuth en `src/features/oauth/`**:
  - `GET /oauth/authorize` — inicia el flujo, redirige a login o consent.
  - `POST /oauth/authorize` — registra el consent del usuario y emite el
    `authorization_code`.
  - `POST /oauth/token` — intercambia código por `access_token` (+ opcional
    `id_token` para scope `openid`) y refresca tokens.
  - `GET /oauth/userinfo` — claims OIDC (`sub`, `email`, `name`, ...)
    según los scopes concedidos.
  - `POST /oauth/introspect` — RFC 7662, requiere `client_secret`.
  - `POST /oauth/revoke` — RFC 7009, idempotente.
  - `GET /.well-known/openid-configuration` y `GET /.well-known/jwks.json`
    para discovery automático por parte de los clientes.
- **Gestión de aplicaciones OAuth para el usuario**: `POST /oauth/apps`,
  `GET /oauth/apps`, `DELETE /oauth/apps/:id`, `POST /oauth/apps/:id/regenerate-secret`.
  El `client_secret` se entrega en plano una sola vez y se persiste como
  hash bcrypt (cost 10). Las redirect URIs se validan estrictamente.
- **Modelos Prisma `OAuthApp`, `OAuthAuthCode`, `OAuthToken`** con migración
  SQL. Códigos de autorización con TTL de 10 minutos y flag `used` para
  impedir reuso; tokens de acceso de 1 hora firmados con HS256 (mismo
  `JWT_SECRET`), refresh tokens de 96 caracteres aleatorios criptográficos.
- **PKCE (RFC 7636)** con métodos `S256` y `plain`. Cliente público
  (sin `client_secret`) requiere `code_verifier` obligatorio.
- **Rate limit** de 20 req/min en `/oauth/authorize` y `/oauth/token` para
  contener fuerza bruta sobre el endpoint de token.
- **Variable de entorno `SERVER_URL`** (defecto `http://localhost:3000`) usada
  como `issuer` en discovery y en los claims `iss` de los `id_token`.

#### Changed

- `app.config.ts` añade `serverUrl` además del existente `frontendUrl`.

---

## [0.1.0] - 2026-05-14

### Sprint 5 — Seguridad completa y observabilidad

#### Added

- **Flujo de recuperación de contraseña**: `POST /auth/forgot-password` y `POST /auth/reset-password` con tokens Redis (TTL 1 h). Nunca revela si el email existe; el token de reset expira y es de un solo uso.
- **Verificación de email**: `POST /auth/send-verification` y `GET /auth/verify-email` con tokens Redis (TTL 24 h). El email de verificación se envía automáticamente tras el registro.
- **Templates HTML de email**: layout oscuro con marca propia (`baseLayout`) reutilizado en OTP, reset de contraseña, verificación de email y aviso de pocos backup codes.
- **Filtro global de excepciones**: normaliza todos los errores a `{ statusCode, error, message, timestamp }` y registra excepciones no-HTTP en el servidor.
- **Módulo de health check**: `GET /health` (liveness rápido) y `GET /health/detailed` (ping a Prisma + Redis).
- **Campo `emailVerified`** en el modelo User (migración Prisma incluida); expuesto en `UserResponseDto`.
- **Registro de auditoría** para eventos de activación/desactivación de 2FA y consumo de backup codes.
- **Aviso por email de pocos backup codes** cuando quedan ≤ 2 códigos.

#### Changed

- Protección CSRF extendida a todos los endpoints mutantes: `enable-2fa`, `verify-2fa`, `disable-2fa`, `2fa/cancel`, `logout`, `DELETE /sessions`, `DELETE /sessions/others`, `DELETE /sessions/:id`.
- `frontendUrl` añadido a `app.config.ts` para generar los links de reset y verificación.

#### Fixed

- Las llamadas a `AuditLogService` y `EmailService` en `consumeBackupCode` eran TODOs sin implementar; ahora están completamente conectadas.

---

## [Unreleased]

### Sprint 0 — Auditoría de seguridad

#### Fixed

- **Acceso no autenticado a datos de usuario**: se elimina `UserController`,
  que exponía `POST /users` y `GET /users/:id` sin guard y devolvía el
  objeto Prisma crudo (hash de contraseña, `totpSecret` cifrado y
  `backupCodes`). El `UserService` se mantiene y sigue siendo consumido
  por `AuthService` y las estrategias OAuth.
- **Endpoint inalcanzable por orden de rutas**: `DELETE /auth/sessions/others`
  estaba declarado después de `DELETE /auth/sessions/:id`, por lo que Nest
  lo interpretaba como `id = "others"`. Se reordenan los handlers para
  que `others` quede antes del parámetro dinámico.
- **Revocación de sesiones ajenas**: `AuthController.revoke` aceptaba
  cualquier `sessionId` sin comprobar propiedad. `AuthService.revokeSession`
  ahora carga la sesión, valida que pertenezca al usuario autenticado y
  lanza `ForbiddenException` en caso contrario (`NotFoundException` si no
  existe).
- **Contraseñas predecibles en alta OAuth**: las estrategias de Google y
  Discord generaban la contraseña del usuario nuevo como
  `accessToken.slice(0, 10)`. Se sustituye por `randomBytes(32).toString('hex')`
  para impedir el login local sobre cuentas creadas por SSO.

#### Security

- **Credenciales hardcodeadas en `docker-compose.yml`**: se eliminan los
  literales `postgres:password`. Postgres y Redis pasan a leer
  `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` y `REDIS_PASSWORD`
  desde el entorno.
- **Puertos de datos expuestos al host**: los mapeos `5432:5432` y
  `6379:6379` se reemplazan por `expose:`, manteniendo Postgres y Redis
  únicamente dentro de la red de Compose.
- **Redis sin autenticación**: el servicio Redis arranca ahora con
  `--requirepass ${REDIS_PASSWORD}` y la URL de conexión del backend
  incluye el password.

### Sprint 1 — Endurecimiento

#### Fixed

- **CORS no configurado**: se añade `app.enableCors()` con lista de
  orígenes permitidos derivada de `APP_URL` y `credentials: true`. Sin
  esto el navegador rechazaba peticiones cross-origin al backend.
- **Rate limit roto detrás de proxy**: se añade `app.set('trust proxy', 1)`
  para que `req.ip` refleje la IP real del cliente en lugar de la del
  load balancer.
- **`sameSite: 'strict'` en callbacks OAuth**: los callbacks de Google y
  Discord son navegaciones cross-site; las cookies marcadas como `strict`
  no se envían en el redirect subsiguiente. Solo los callbacks cambian a
  `'lax'`; todos los demás endpoints mantienen `'strict'`.
- **Backup codes generados con `Math.random()`**: se reemplaza por
  `randomBytes(5).toString('hex')`, que usa el pool de entropía del SO.
- **Secret TOTP devuelto al cliente en `enable-2fa`**: el campo `secret`
  se eliminó de la respuesta; el QR code ya lo contiene y devolverlo
  duplicaba la superficie de exposición.
- **Regeneración de 2FA sin verificación**: si el usuario ya tenía 2FA
  activo, `enable-2fa` permitía rotar el secret sin presentar el TOTP
  actual. Ahora exige `currentTotpCode` antes de reemplazar el factor.
- **TOTP en query string en notas**: `GET /notes?totpCode=...` aparecía
  en logs HTTP, historial y Referer. Se mueve a la cabecera
  `X-TOTP-Code` en el controlador; los DTOs de query ya no son necesarios.

#### Security

- **Algoritmo JWT no fijado**: se añade `signOptions: { algorithm: 'HS256' }`
  en `JwtModule.register` y `algorithms: ['HS256']` en cada
  `verifyAsync`, cerrando ataques de confusión de algoritmo (`alg: none`,
  RS256-sobre-HS256).

### Sprint 2 — Limpieza y calidad

#### Added

- **Módulo Redis global `RedisModule`**: se crea `src/modules/redis/` con
  un proveedor `REDIS_CLIENT` marcado como `@Global()`. Los cinco servicios
  que antes abrían su propia conexión TCP (`AuthService`, `SessionService`,
  `OtpService`, `NoteService`, `RateLimitGuard`) pasan a inyectar el cliente
  compartido, reduciendo conexiones activas de 5 a 1.
- **Modelo `AuditLog` en Prisma**: se añade la tabla con `userId`, `action`,
  `severity`, `ipAddress`, `userAgent` y `metadata JSON`, con índices en
  `userId`, `action` y `createdAt`. Se incluye la migración SQL en
  `prisma/migrations/`. `AuditLogService` deja de hacer `console.log` y
  persiste cada evento en la DB; fallos son silenciados para no interrumpir
  la petición principal.

#### Removed

- **Boilerplate `AppController` / `AppService`**: se eliminan el endpoint
  `GET /` ("Hello World"), su spec y el e2e spec asociado.
- **`HealthController`**: nunca fue registrado en ningún módulo; creaba su
  propia conexión Redis y no era alcanzable. Eliminado.
- **`CookieHelper`**: helper nunca importado; la lógica existía duplicada
  inline en el controller.
- **`VerifyOtpDto`** y **`JwtPayload`**: DTOs e interfaces sin uso real.
- **`NotesFeatureModule`**: clase de módulo incrustada al final de
  `notes.service.ts`; el módulo real vive en `notes.module.ts`.

#### Changed (deps)

- Eliminadas 6 dependencias sin uso: `@keyv/redis`, `@nestjs/cache-manager`,
  `cache-manager`, `dotenv`, `uuid`, `zod`.

### Sprint 3 — Robustez y calidad

#### Added

- **Bloqueo de cuenta por email**: `AuthService.login` introduce bloqueo
  temporal basado en Redis (`lockout:<email>`, TTL 15 min) tras 5 intentos
  fallidos consecutivos. Cuenta separada de la limitación por IP ya existente,
  por lo que protege también desde IPs distintas. El contador se limpia en
  cada login exitoso.
- **`parseDuration` centralizado**: el helper que convierte cadenas de
  duración (`15m`, `7d`, `3600`) a segundos existía duplicado como método
  privado en `AuthController` y `TokenService`. Se mueve a
  `src/common/utils/parse-duration.ts` y ambas clases pasan a importarlo.
  `TokenService` aplica un fallback seguro (3 600 s / 7 días) cuando el
  valor de configuración es inválido, evitando JWTs sin expiración.

#### Fixed

- **OTP generado con `Math.random()`**: `OtpService.generate` producía
  códigos de 6 dígitos con PRNG no criptográfico. Se sustituye por
  `randomBytes(4).readUInt32BE(0) % 900000 + 100000`, que lee del pool de
  entropía del SO.
- **`throw new Error(...)` en `OtpService.verify`**: al superar el límite
  de intentos OTP el servicio lanzaba un `Error` genérico, que NestJS
  convierte en HTTP 500. Ahora lanza `UnauthorizedException` para devolver
  correctamente HTTP 401.

### Sprint 4 — Limpieza final

#### Changed

- Eliminados comentarios inline en español en `auth.service.ts` y
  `otp.service.ts` que describían lo que el código ya expresaba.

[Unreleased]: https://github.com/Kamerr/nest-auth-hybrid/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Kamerr/nest-auth-hybrid/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Kamerr/nest-auth-hybrid/releases/tag/v0.1.0
