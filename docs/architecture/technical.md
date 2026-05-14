# Arquitectura técnica — VaultAuth

Decisiones de diseño, flujos internos y razonamiento de seguridad del sistema VaultAuth.

---

## Tabla de contenidos

- [Visión general del sistema](#visión-general-del-sistema)
- [Flujo completo: Authorization Code + PKCE](#flujo-completo-authorization-code--pkce)
  - [Paso 0: usuario no autenticado](#paso-0-usuario-no-autenticado)
  - [Paso 1–4: autorización y consentimiento](#paso-14-autorización-y-consentimiento)
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

```mermaid
graph TD
    subgraph Frontends
        Portal["next-auth-hybrid :3001\n/login · /oauth/consent · /developer"]
        Demo["vaultauth-demo-app :3002\nNextAuth v5 + custom provider"]
    end

    subgraph Backend ["nest-auth-hybrid :3000"]
        Auth["/auth/*\nAutenticación propia\n(sesión / JWT / 2FA)"]
        OAuth["/oauth/*\nAuthorization Server\n(RFC 6749 + OIDC)"]
        WK["/.well-known/*\nDescubrimiento OIDC"]
    end

    PG[("PostgreSQL\nusers · oauth_apps\nauth_codes · tokens")]
    Redis[("Redis\nsession · oauth_req\nrate_limit · lockout")]

    Portal -->|"Server Actions / fetch"| Auth
    Portal -->|"consent flow"| OAuth
    Demo -->|"OAuth 2.0 flows"| OAuth

    Auth --> PG
    Auth --> Redis
    OAuth --> PG
    OAuth --> Redis
```

---

## Flujo completo: Authorization Code + PKCE

### Paso 0: Usuario no autenticado

```mermaid
sequenceDiagram
    actor Browser as Navegador
    participant Demo as Demo App :3002
    participant Backend as Backend :3000
    participant Portal as Portal :3001
    participant DB as PostgreSQL
    participant Redis

    Demo->>Backend: GET /oauth/authorize?response_type=code&client_id=...&code_challenge=...
    Backend->>DB: findOAuthAppByClientId(clientId)
    Backend->>Backend: validateAuthRequest()
    Note over Backend: sessionId cookie: ausente
    Backend-->>Browser: 302 → /login?from=/oauth/authorize?...

    Browser->>Portal: GET /login?from=...
    Portal-->>Browser: HTML LoginForm (from en campo hidden)
    Browser->>Portal: submit email + password
    Note over Portal: server action loginAction()
    Portal->>Backend: POST /auth/login
    Backend->>Backend: bcrypt.compare(password, hash)
    Backend->>Redis: SET session:<uuid> { userId, expiresAt }
    Backend-->>Portal: 200 { accessToken } + Set-Cookie: sessionId
    Note over Portal: loginAction devuelve { redirectTo } — NO llama redirect()
    Portal-->>Browser: window.location.href = /oauth/authorize?...
```

**Por qué `window.location.href` y no `redirect()` de Next.js:**
`redirect()` en un server action desencadena navegación suave (soft-nav). El servidor
sigue la 302 del backend sin actualizar la URL del navegador. `useSearchParams()` en
`/oauth/consent` lee desde la URL del navegador — que sigue siendo `/oauth/authorize?...`
— y devuelve `request_id = null`. `window.location.href` provoca un GET real del
navegador que sí actualiza la URL correctamente.

---

### Paso 1–4: Autorización y consentimiento

```mermaid
sequenceDiagram
    actor Browser as Navegador
    participant Backend as Backend :3000
    participant Portal as Portal :3001
    participant Redis
    participant DB as PostgreSQL

    Browser->>Backend: GET /oauth/authorize?... (con sessionId cookie)
    Backend->>Redis: GET session:<id>
    Redis-->>Backend: { userId, expiresAt }
    Backend->>Backend: getSessionUserId() — verifica expiresAt

    Backend->>Redis: SET oauth_req:<uuid> { clientId, redirectUri, scopes, state, codeChallenge, userId, appName } EX 300
    Backend-->>Browser: 302 → /oauth/consent?request_id=<uuid>&app_name=...

    Browser->>Portal: GET /oauth/consent?request_id=<uuid>
    Note over Portal: useSearchParams() → request_id
    Portal->>Backend: GET /oauth/consent/<uuid>
    Backend->>Redis: GET oauth_req:<uuid>
    Backend-->>Portal: { clientId, scopes, appName }
    Portal-->>Browser: HTML ConsentCard

    Browser->>Portal: click "Autorizar"
    Portal->>Backend: POST /oauth/authorize { request_id, approved: true }
    Note over Backend: issueAuthCode()
    Backend->>Redis: GET oauth_req:<uuid> — verifica userId == sesión activa
    Backend->>DB: CREATE OAuthAuthCode { code, clientId, userId, used: false, expiresAt: +10min }
    Backend->>Redis: DEL oauth_req:<uuid>
    Backend-->>Portal: { redirectTo: redirect_uri?code=...&state=... }
    Portal-->>Browser: window.location.href = redirect_uri?code=...
```

---

### Paso 5: Intercambio de código

```mermaid
sequenceDiagram
    participant Demo as Demo App :3002
    participant Backend as Backend :3000
    participant DB as PostgreSQL

    Demo->>Backend: POST /oauth/token<br/>grant_type=authorization_code<br/>code=... redirect_uri=... client_id=...<br/>[code_verifier | client_secret]

    Backend->>DB: findOAuthAuthCode(code)
    DB-->>Backend: authCode { used, expiresAt, clientId, redirectUri, codeChallenge }

    alt PKCE (cliente público)
        Backend->>Backend: SHA-256(code_verifier) base64url == codeChallenge
    else client_secret (cliente confidencial)
        Backend->>DB: findOAuthAppByClientId(clientId)
        Backend->>Backend: bcrypt.compare(clientSecret, app.clientSecret)
    end

    Backend->>Backend: verifica !used · !expirado · clientId · redirectUri exacta
    Backend->>DB: markOAuthAuthCodeUsed(id)
    Backend->>DB: CREATE OAuthToken { accessToken (JWT HS256 1h), refreshToken (96 bytes hex) }
    Backend-->>Demo: { access_token, refresh_token, token_type, expires_in, scope }
```

---

### Paso 6–N: Uso del access token

```mermaid
sequenceDiagram
    participant Demo as Demo App :3002
    participant Backend as Backend :3000
    participant DB as PostgreSQL

    Demo->>Backend: GET /oauth/userinfo<br/>Authorization: Bearer access_token
    Backend->>Backend: jwt.verify(token, secret)
    Backend->>Backend: verifica type === "oauth_access"
    Backend->>DB: findOAuthTokenByAccess(token) — verifica !revoked
    Backend->>Backend: filtra claims según scopes del token
    Backend-->>Demo: { sub, name, email, email_verified }

    Note over Demo,Backend: Cuando el access_token expira…

    Demo->>Backend: POST /oauth/token<br/>grant_type=refresh_token<br/>refresh_token=...
    Backend->>DB: findOAuthTokenByRefresh(refreshToken)
    Backend->>DB: revokeOAuthToken(old.id)
    Note over Backend: rotación — token anterior queda revocado
    Backend->>DB: CREATE OAuthToken { newAccessToken, newRefreshToken }
    Backend-->>Demo: { access_token, refresh_token }
```

---

## Flujo de sesión híbrida (VaultAuth propio)

El backend admite dos mecanismos paralelos para autenticar llamadas de la propia interfaz de VaultAuth:

```mermaid
flowchart TD
    REQ["Petición entrante"] --> GUARD{"HybridAuthGuard"}

    GUARD -->|"Header Authorization: Bearer token"| JWT["JwtAuthGuard\njwt.verify(token, secret)\n→ payload.sub → user"]
    GUARD -->|"Cookie sessionId"| SESSION["SessionAuthGuard\nRedis GET session:id\nverifica expiresAt\nSELECT user FROM DB\n→ user"]

    JWT --> OK["✅ req.user = { id, email }"]
    SESSION --> OK
    GUARD -->|"ninguno"| ERR["❌ 401 Unauthorized"]
```

La sesión vive en Redis con TTL, no en base de datos: invalidación inmediata O(1) sin JOINs.
La doble verificación (Redis TTL + `expiresAt` explícito) cubre el edge case donde Redis
no expira exactamente al segundo.

---

## Almacenamiento: Redis vs PostgreSQL

| Dato                         | Dónde      | TTL                           | Motivo                             |
| ---------------------------- | ---------- | ----------------------------- | ---------------------------------- |
| Sesiones de usuario          | Redis      | 7 días (sliding)              | Invalidación inmediata, sin JOIN   |
| Solicitudes OAuth pendientes | Redis      | 5 min                         | Efímero, no necesita persistencia  |
| Rate limit counters          | Redis      | 60 s (ventana)                | Atómico con INCR/EX                |
| Lockout de cuenta            | Redis      | 15 min                        | Temporal, reset automático         |
| Auth codes                   | PostgreSQL | 10 min (campo `expiresAt`)    | Auditoría, single-use flag         |
| Access/Refresh tokens        | PostgreSQL | Access: 1h / Refresh: sin TTL | Revocación por registro, auditoría |
| Aplicaciones OAuth           | PostgreSQL | Permanente                    | Configuración de cliente           |
| Usuarios                     | PostgreSQL | Permanente                    | Identidad principal                |

**¿Por qué los auth codes van a PostgreSQL y no a Redis?**
Los códigos se marcan como `used` al consumirse. Redis solo admite TTL, no estados
adicionales. Con PostgreSQL el flag `used` garantiza exactamente-una-vez incluso en
escenarios de reintentos concurrentes.

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
En un sistema de un solo servidor que controla emisión y verificación, HS256 elimina
la complejidad de gestión de claves públicas sin reducir la seguridad. RS256 aporta
valor cuando recursos externos verifican tokens sin pasar por el authorization server;
el endpoint `/oauth/introspect` cubre esa función para terceros.

**¿Por qué no hay `id_token`?**
Se optó por centralizar los claims de identidad en `/oauth/userinfo` en lugar de emitir
un `id_token` por separado. Elimina la duplicación de claims entre el JWT del token
endpoint y el userinfo, y simplifica la implementación. Los clientes usan el endpoint
estándar OIDC que ya tienen disponible.

### Refresh token — opaco

96 bytes aleatorios codificados en hex (192 caracteres, 768 bits de entropía).
Almacenado en PostgreSQL como texto plano porque actúa como clave de búsqueda.
La seguridad reside en la entropía, no en cifrado.

**Rotación en cada uso:** el token anterior queda revocado y se emite un par nuevo.
Si un token robado se usa después del refresh legítimo → el atacante recibe 401.
Si lo usa antes → el usuario legítimo pierde la sesión al siguiente refresh, señal de compromiso.

---

## Decisiones de diseño

### 1. Consent page en el frontend, no en el backend

El backend valida y almacena la solicitud OAuth en Redis, luego redirige al frontend
(`/oauth/consent?request_id=...`). El frontend renderiza la pantalla de consentimiento
y llama al backend para aprobar/denegar.

**Por qué:** permite usar el sistema de diseño y componentes React existentes.
El backend solo valida; nunca renderiza HTML.

### 2. `request_id` como clave de Redis en lugar de pasar parámetros por URL

Los parámetros OAuth completos (clientId, redirectUri, scopes, state, codeChallenge)
se almacenan en Redis bajo un UUID. Solo el UUID viaja en la URL de consentimiento.

**Por qué:**

- Evita URLs largas con datos sensibles visibles en logs de servidor
- Previene manipulación de parámetros en la URL de consentimiento
- El backend revalida todo desde Redis al momento de emitir el código

### 3. `from` param en login para preservar el flujo OAuth

Cuando el usuario no está autenticado, el backend redirige a:

```
/login?from=/oauth/authorize?response_type=code&client_id=...
```

El login form preserva `from` en un campo hidden y lo usa al redirigir tras autenticación.

**Alternativa descartada:** guardar el destino en la sesión Redis. Falla cuando el
usuario tiene múltiples pestañas abiertas o múltiples flujos OAuth en paralelo.

### 4. `getSessionUserId` manual en lugar de `HybridAuthGuard` en `/oauth/authorize`

`GET /oauth/authorize` necesita devolver 302 al login cuando el usuario no está
autenticado, en lugar de lanzar 401. `HybridAuthGuard` solo lanza excepciones, no redirige.

Solución: leer la cookie `sessionId` manualmente y verificarla con `getSessionUserId()`,
manteniéndola en OAuthService para tener toda la lógica de sesión OAuth en un solo lugar.

### 5. Soporte de `client_secret_basic` sin middleware global

El header `Authorization: Basic base64(id:secret)` se decodifica en el handler de
`POST /oauth/token` en lugar de en un interceptor global, evitando colisión con
`HybridAuthGuard` que también procesa `Authorization: Bearer`.

---

## Decisiones de seguridad

### PKCE obligatorio para clientes públicos (RFC 7636)

Los clientes sin `client_secret` deben incluir `code_challenge` (S256 preferido).
Sin PKCE, un atacante que intercepte el authorization code puede canjearlo sin secreto.

**Validación S256:** `base64url(SHA-256(code_verifier)) === code_challenge`

### Validación exacta de `redirect_uri`

Sin prefijos, wildcards ni comparaciones de origen. La URI debe coincidir exactamente
con la registrada en DB. Una URI parcialmente coincidente permitiría redirigir tokens
a un dominio controlado por el atacante.

### Rate limiting en `/oauth/authorize` y `/oauth/token`

20 req/min por IP con Redis (`INCR` + `EX`). Previene fuerza bruta sobre el flujo
de autorización sin dependencias externas adicionales.

### Bcrypt para `client_secret`

Almacenado como hash bcrypt (factor 10). El texto plano solo se devuelve una vez al
crear la app. Si la DB se ve comprometida, los secretos siguen siendo inútiles.

### Lockout de cuenta tras intentos fallidos

5 intentos fallidos → bloqueo de 15 minutos en Redis. El lockout es por email (no por IP)
para no penalizar redes NAT. El contador se resetea en login exitoso.

### Validación de `userId` al emitir el código

`issueAuthCode(requestId, userId)` verifica que el `userId` de la sesión activa coincide
con el almacenado en la solicitud OAuth. Previene que un usuario apruebe el consentimiento
de otro usuario si la sesión cambia durante el flujo.

### CSRF en endpoints con efecto de escritura

`POST /oauth/apps`, `DELETE /oauth/apps/:id`, `POST /oauth/apps/:id/regenerate-secret`
y `POST /oauth/authorize` (consent) requieren `CsrfGuard`. Los endpoints del token
(`/token`, `/introspect`, `/revoke`) son server-to-server y no requieren CSRF.

---

## Concurrencia y condiciones de carrera

### Auth code single-use

`markOAuthAuthCodeUsed` ejecuta un UPDATE en DB. Si dos peticiones simultáneas intentan
usar el mismo código, la segunda encontrará `used = true` y fallará.

### Refresh token race

Si dos peticiones simultáneas usan el mismo refresh token, ambas pasan la validación
`!revoked` antes de que ninguna ejecute `revokeOAuthToken`. La primera en completar el
UPDATE gana; la segunda podría emitir un segundo par de tokens válido por 1 hora.

Este es un tradeoff aceptado. La solución robusta requeriría `SELECT FOR UPDATE` o un
lock en Redis, añadiendo latencia en cada refresh. Para el perfil de uso de este sistema
no está justificado.
