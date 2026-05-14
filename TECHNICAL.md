# Arquitectura técnica — VaultAuth

Decisiones de diseño, flujos internos y razonamiento de seguridad del sistema VaultAuth.

---

## Tabla de contenidos

- [Visión general del sistema](#visión-general-del-sistema)
- [Flujo completo: Authorization Code + PKCE](#flujo-completo-authorization-code--pkce)
  - [Paso 0: unauthenticated user](#paso-0-usuario-no-autenticado)
  - [Paso 1–4: autorización](#paso-14-autorización-y-consentimiento)
  - [Paso 5: intercambio de código](#paso-5-intercambio-de-código)
  - [Paso 6–N: uso del access token](#paso-6n-uso-del-access-token)
- [Flujo de sesión híbrida (VaultAuth propio)](#flujo-de-sesión-híbrida-vaultauth-propio)
- [Almacenamiento: Redis vs PostgreSQL](#almacenamiento-redis-vs-postgresql)
- [Estrategia de tokens](#estrategia-de-tokens)
- [Decisiones de diseño](#decisiones-de-diseño)
- [Decisiones de seguridad](#decisiones-de-seguridad)
- [Concurrencia y condiciones de carrera](#concurrencia-y-condiciones-de-carrera)

---

## Visión general del sistema

```
┌──────────────────────────────────────────────────────────────┐
│                    NAVEGADOR DEL USUARIO                      │
└──────────────────────────────────────────────────────────────┘
         │ HTTP                              │ HTTP
         ▼                                  ▼
┌────────────────────┐            ┌──────────────────────┐
│  next-auth-hybrid  │            │  vaultauth-demo-app  │
│  Next.js 16 :3001  │            │  Next.js 15 :3002    │
│  ─────────────     │            │  NextAuth v5         │
│  /login            │            │  /dashboard          │
│  /oauth/consent    │            │  (consume la API)    │
│  /developer        │            └──────────────────────┘
└────────────────────┘
         │ fetch (server actions / api routes)
         ▼
┌──────────────────────────────────────────────────────────────┐
│                   nest-auth-hybrid  :3000                     │
│  ─────────────────────────────────────────────────────────   │
│  /auth/*          Autenticación propia (sesión/JWT/2FA)       │
│  /oauth/*         Authorization Server (RFC 6749 + OIDC)      │
│  /.well-known/*   Descubrimiento OIDC                         │
└──────────────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
┌─────────────┐          ┌─────────────────┐
│  PostgreSQL │          │     Redis        │
│  (Prisma)   │          │                 │
│  ─────────  │          │  session:<id>   │
│  users      │          │  oauth_req:<id> │
│  oauth_apps │          │  rate_limit:*   │
│  auth_codes │          │  lockout:*      │
│  tokens     │          └─────────────────┘
└─────────────┘
```

---

## Flujo completo: Authorization Code + PKCE

### Paso 0: Usuario no autenticado

```
Demo App (:3002)          VaultAuth Backend (:3000)      VaultAuth Frontend (:3001)
     │                            │                               │
     │── GET /api/auth/signin ──► │                               │
     │   NextAuth inicia flujo    │                               │
     │                            │                               │
     │── GET /oauth/authorize? ──►│                               │
     │   response_type=code       │                               │
     │   client_id=...            │                               │
     │   redirect_uri=...         │                               │
     │   code_challenge=...       │                               │
     │   code_challenge_method=S256                               │
     │                            │                               │
     │                            │ validateAuthRequest()         │
     │                            │ ─ verifica client_id en DB   │
     │                            │ ─ valida redirect_uri exacta │
     │                            │ ─ verifica scopes permitidos │
     │                            │                               │
     │                            │ sessionId cookie? NO          │
     │                            │                               │
     │◄── 302 /login?from=... ────│                               │
     │    (preserva params OAuth) │                               │
     │                            │                               │
     │────────────────────────────────────► GET /login?from=...  │
     │                                                            │
     │                      [usuario introduce credenciales]      │
     │                                                            │
     │────────────────────────────────────► POST /auth/login      │
     │                            │◄───────────────────────────── │
     │                            │ valida email+password          │
     │                            │ ¿2FA activo? → tempToken      │
     │                            │ ¿no 2FA? → Set-Cookie:sessionId│
     │                            │──────────────────────────────►│
     │                            │                 setAuthCookies │
     │                            │                               │
     │                            │      window.location.href     │
     │◄───────────────────────────────────── redirectTo=/oauth/authorize?...
```

**Por qué `window.location.href` y no `redirect()` de Next.js:**  
`redirect()` en un server action desencadena navegación suave (soft-nav) en Next.js.
El servidor sigue el 302 del backend sin actualizar la URL del navegador.
`useSearchParams()` en `/oauth/consent` lee desde la URL del navegador — que sigue
siendo `/oauth/authorize?...` — y devuelve `request_id = null`, rompiendo el flujo.
`window.location.href` provoca un GET real del navegador que sí actualiza la URL.

---

### Paso 1–4: Autorización y consentimiento

```
Navegador                VaultAuth Backend (:3000)      VaultAuth Frontend (:3001)
    │                            │                               │
    │── GET /oauth/authorize ───►│                               │
    │   (con sessionId cookie)   │                               │
    │                            │ getSessionUserId()            │
    │                            │ ─ lee session:<id> de Redis   │
    │                            │ ─ verifica expiresAt          │
    │                            │ ─ devuelve userId             │
    │                            │                               │
    │                            │ storeAuthRequest()            │
    │                            │ ─ genera requestId (UUID v4)  │
    │                            │ ─ guarda en Redis 5 min:      │
    │                            │   oauth_req:<uuid> = {        │
    │                            │     clientId, redirectUri,    │
    │                            │     scopes, state,            │
    │                            │     codeChallenge,            │
    │                            │     codeChallengeMethod,      │
    │                            │     userId, appName           │
    │                            │   }                           │
    │                            │                               │
    │◄── 302 /oauth/consent?─────│                               │
    │    request_id=<uuid>        │                               │
    │    app_name=...             │                               │
    │    scope=...                │                               │
    │                            │                               │
    │────────────────────────────────────────► GET /oauth/consent│
    │                            │               useSearchParams  │
    │                            │               → request_id    │
    │                            │                               │
    │                            │◄─── GET /oauth/consent/<id> ──│
    │                            │     (carga info del request)  │
    │                            │──────────────────────────────►│
    │                            │   {clientId,scopes,appName}   │
    │                            │                               │
    │◄───────────────────────────────────── muestra pantalla     │
    │                                       de consentimiento     │
    │                                                            │
    │────────────────────────────────────── POST /oauth/authorize│
    │                                       {request_id, approved}
    │                            │◄──────────────────────────────│
    │                            │ issueAuthCode()               │
    │                            │ ─ revalida userId vs request  │
    │                            │ ─ crea auth_code en DB        │
    │                            │   (64 bytes hex, TTL 10 min,  │
    │                            │    single-use flag)           │
    │                            │ ─ elimina oauth_req de Redis  │
    │                            │ ─ construye redirect URL      │
    │                            │──────────────────────────────►│
    │                            │   { redirectTo: <url>+code }  │
    │◄───────────────────────────────────── window.location.href │
```

---

### Paso 5: Intercambio de código

```
Demo App (:3002)                          VaultAuth Backend (:3000)
    │                                             │
    │── POST /oauth/token ───────────────────────►│
    │   grant_type=authorization_code             │
    │   code=<hex>                                │
    │   redirect_uri=...                          │
    │   client_id=...                             │
    │   [client_secret o code_verifier]           │
    │                                             │
    │                                             │ findOAuthAuthCode(code)
    │                                             │ ─ verifica: !used, !expirado
    │                                             │ ─ verifica: clientId coincide
    │                                             │ ─ verifica: redirectUri exacta
    │                                             │
    │                                             │ Si hay codeChallenge:
    │                                             │   PKCE S256: SHA-256(verifier)
    │                                             │     == challenge (base64url)
    │                                             │   plain: verifier == challenge
    │                                             │
    │                                             │ Si hay clientSecret:
    │                                             │   bcrypt.compare(secret, hash)
    │                                             │
    │                                             │ markOAuthAuthCodeUsed(id)
    │                                             │ issueTokens():
    │                                             │   access_token: JWT HS256 1h
    │                                             │   refresh_token: 96 bytes hex
    │                                             │   persiste en DB
    │                                             │
    │◄── { access_token, refresh_token, ... } ────│
```

---

### Paso 6–N: Uso del access token

```
Demo App (:3002)              VaultAuth Backend (:3000)
    │                                 │
    │── GET /oauth/userinfo ──────────►│
    │   Authorization: Bearer <jwt>   │
    │                                 │ jwt.verify(token, secret)
    │                                 │ verifica type === "oauth_access"
    │                                 │ consulta DB: token no revocado
    │                                 │ filtra claims por scope
    │◄── { sub, name, email, ... } ───│
    │                                 │
    │── (refresh) ────────────────────►│
    │   grant_type=refresh_token      │
    │   refresh_token=...             │
    │                                 │ findOAuthTokenByRefresh()
    │                                 │ revokeOAuthToken(old)  ← rotación
    │                                 │ issueTokens() → new pair
    │◄── { access_token, refresh_token }│
```

---

## Flujo de sesión híbrida (VaultAuth propio)

El backend admite dos mecanismos paralelos para autenticar llamadas de la propia interfaz de VaultAuth:

```
Petición entrante
      │
      ▼
HybridAuthGuard
      │
      ├─── ¿Header Authorization: Bearer <token>? ──► JwtAuthGuard
      │         jwt.verify() → payload.sub → user
      │
      └─── ¿Cookie sessionId? ──────────────────────► SessionAuthGuard
                Redis GET session:<id>
                verifica expiresAt
                SELECT user FROM DB (confirma que existe)
                → user
```

La sesión se almacena en Redis con TTL, no en base de datos. Esto permite
invalidación inmediata sin JOINs y logout O(1).

La doble verificación (Redis TTL + expiresAt explícito) protege contra
el edge case donde Redis no expira exactamente al segundo.

---

## Almacenamiento: Redis vs PostgreSQL

| Dato                         | Dónde      | TTL                                   | Motivo                             |
| ---------------------------- | ---------- | ------------------------------------- | ---------------------------------- |
| Sesiones de usuario          | Redis      | 7 días (sliding)                      | Invalidación inmediata, sin JOIN   |
| Solicitudes OAuth pendientes | Redis      | 5 min                                 | Efímero, no necesita persistencia  |
| Rate limit counters          | Redis      | 60 s (ventana)                        | Atómico con INCR/EX                |
| Lockout de cuenta            | Redis      | 15 min                                | Temporal, reset automático         |
| Auth codes                   | PostgreSQL | 10 min (campo expiresAt)              | Auditoría, single-use flag         |
| Access/Refresh tokens        | PostgreSQL | Access: 1h (campo) / Refresh: sin TTL | Revocación por registro, auditoría |
| Aplicaciones OAuth           | PostgreSQL | Permanente                            | Configuración de cliente           |
| Usuarios                     | PostgreSQL | Permanente                            | Identidad principal                |

**¿Por qué los auth codes van a PostgreSQL y no a Redis?**  
Los códigos se marcan como `used` al consumirse (single-use). Redis solo admite
TTL, no estados adicionales. Mover la lógica a Postgres simplifica la garantía
de exactamente-una-vez sin race conditions en escenarios de reintentos.

---

## Estrategia de tokens

### Access token — JWT HS256

```json
{
  "sub": "user_id",
  "client_id": "app_client_id",
  "scope": "openid profile email",
  "jti": "uuid-v4",
  "type": "oauth_access",
  "iat": 1715696400,
  "exp": 1715700000
}
```

**¿Por qué HS256 y no RS256?**  
En un sistema de un solo servidor que controla tanto la emisión como la verificación,
HS256 elimina la complejidad de gestión de claves públicas sin reducir la seguridad.
RS256 aporta valor cuando recursos externos verifican tokens sin pasar por el
authorization server. El endpoint `/oauth/introspect` cumple esa función para terceros.

**¿Por qué no hay `id_token`?**  
La especificación OIDC requiere `id_token` en respuestas al token endpoint cuando se
solicita el scope `openid`. Se tomó la decisión pragmática de omitirlo y centralizar
los claims de identidad en `/oauth/userinfo`. Esto simplifica la implementación y
elimina duplicación de claims entre el JWT y el userinfo. Los clientes que necesiten
claims de identidad usan el endpoint estándar.

### Refresh token — opaco

96 bytes aleatorios codificados en hex (192 caracteres). Almacenado en PostgreSQL
como texto plano porque actúa como clave primaria de búsqueda. La seguridad reside
en la entropía (96 bytes = 768 bits), no en cifrado.

**Rotación de refresh tokens:** cada uso revoca el token anterior y emite un par nuevo.
Si un token robado se usa después de que el usuario legítimo ya lo renovó, el atacante
recibe un error y el usuario legítimo pierde su sesión — señal de compromiso.

---

## Decisiones de diseño

### 1. Consent page en el frontend, no en el backend

El backend valida y almacena la solicitud OAuth en Redis, luego redirige al frontend
(`/oauth/consent?request_id=...`). El frontend renderiza la pantalla de consentimiento
y llama al backend para aprobar/denegar.

**Por qué:** Permite que la pantalla de consentimiento use el sistema de diseño y
componentes React existentes. El backend solo valida; nunca renderiza HTML.

### 2. `request_id` como clave de Redis en lugar de pasar todos los parámetros por URL

Los parámetros OAuth completos (clientId, redirectUri, scopes, state, codeChallenge)
se almacenan en Redis bajo un UUID. Solo el UUID viaja en la URL de consentimiento.

**Por qué:**

- Evita URLs largas con datos sensibles (state, codeChallenge) visibles en logs de servidor
- Previene la manipulación de parámetros en la URL de consentimiento
- El backend revalida todo desde Redis al momento de emitir el código

### 3. `from` param en login para preservar el flujo OAuth

Cuando el usuario no está autenticado, el backend redirige a:

```
/login?from=/oauth/authorize?response_type=code&client_id=...
```

El login form preserva `from` en un campo hidden y lo usa al redirigir tras
autenticación exitosa.

**Alternativa descartada:** guardar el destino en la sesión Redis. Complica el
estado de sesión y falla cuando el usuario tiene múltiples pestañas abiertas.

### 4. `getSessionUserId` manual en lugar de `HybridAuthGuard` en `/oauth/authorize`

`GET /oauth/authorize` necesita redirigir al login (302) cuando el usuario no está
autenticado, en lugar de lanzar una excepción HTTP 401. `HybridAuthGuard` solo sabe
lanzar excepciones, no redirigir.

La solución: leer la cookie `sessionId` manualmente y verificarla contra Redis con
`getSessionUserId()`. Mantiene la lógica de sesión en un solo lugar (OAuthService).

### 5. Soporte de `client_secret_basic` sin middleware global

El header `Authorization: Basic base64(id:secret)` se decodifica en el handler de
`POST /oauth/token` en lugar de en un interceptor global. Esto evita colisión con
`HybridAuthGuard` que también procesa headers `Authorization: Bearer`.

---

## Decisiones de seguridad

### PKCE (RFC 7636) obligatorio para clientes públicos

Los clientes sin `client_secret` deben incluir `code_challenge` (S256 preferido).
Sin PKCE, un atacante que intercepte el authorization code en el redirect URI puede
canjearlo sin conocer ningún secreto.

**Validación S256:** `base64url(SHA-256(code_verifier)) === code_challenge`

### Validación exacta de `redirect_uri`

No se permiten prefijos, wildcards ni comparaciones de origen. La URI debe coincidir
exactamente con la registrada en la base de datos. Una URI parcialmente coincidente
podría redirigir tokens a un dominio controlado por el atacante.

### Rate limiting en `/oauth/authorize` y `/oauth/token`

20 req/min por IP. Implementado con Redis (`INCR` + `EX`) sin dependencias externas.
Previene ataques de fuerza bruta sobre el flujo de autorización.

### Bcrypt para `client_secret`

Los secretos de cliente se almacenan como hash bcrypt (factor 10). El valor en texto
plano solo se devuelve una vez al momento de creación. Si la base de datos se ve
comprometida, los secretos siguen siendo inútiles sin el texto plano.

### Lockout de cuenta tras intentos fallidos de login

5 intentos fallidos → bloqueo de 15 minutos en Redis. El contador se resetea en
login exitoso. El bloqueo es por email (no por IP) para no penalizar redes NAT.

### Validación de `userId` al emitir el código

`issueAuthCode(requestId, userId)` verifica que el `userId` de la sesión activa
coincide con el `userId` almacenado en la solicitud OAuth. Previene que un usuario
autenticado apruebe el consentimiento de otro usuario si la sesión cambia durante
el flujo.

### Rotación de refresh tokens

Cada refresh revoca el token anterior. Implementado como operación de dos pasos:
`revokeOAuthToken(old)` → `issueTokens()`. Si un atacante usa el token robado
después del refresh legítimo, recibe `unauthorized`. Si lo usa antes, el usuario
legítimo pierde la sesión al siguiente refresh — señal de alerta.

### CSRF protection en endpoints con efecto de escritura

`POST /oauth/apps`, `DELETE /oauth/apps/:id`, `POST /oauth/apps/:id/regenerate-secret`
y `POST /oauth/authorize` (consent) requieren el guard `CsrfGuard`. Los endpoints
del token (`/oauth/token`, `/oauth/introspect`, `/oauth/revoke`) son accedidos por
backends server-to-server y no requieren CSRF.

---

## Concurrencia y condiciones de carrera

### Auth code single-use

`markOAuthAuthCodeUsed` ejecuta un UPDATE con verificación previa en la misma
transacción. Si dos peticiones simultáneas intentan usar el mismo código, la segunda
recibirá el código marcado como `used` y fallará.

### Refresh token race

Si dos peticiones simultáneas usan el mismo refresh token, ambas pasan la validación
`!revoked` antes de que ninguna ejecute `revokeOAuthToken`. La primera en completar
el UPDATE gana; la segunda encontrará `revoked = true` o emitirá un segundo par de
tokens. Este es un tradeoff aceptado: en la práctica es extremadamente improbable
y el peor caso es un token extra válido por 1 hora.

Una solución robusta requeriría transacciones SELECT FOR UPDATE o un lock en Redis,
añadiendo latencia en cada refresh. Para el perfil de uso de este sistema no está
justificado.
