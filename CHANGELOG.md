# Changelog

Todas las novedades relevantes de este proyecto se documentan aquí. El
formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto adopta [Versionado Semántico](https://semver.org/lang/es/).

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

[Unreleased]: https://github.com/Kamerr/nest-auth-hybrid/compare/main...HEAD
