# Documentación de Endpoints OAuth 2.0 / OIDC

VaultAuth actúa como **Authorization Server** compatible con OAuth 2.0 (RFC 6749) y OpenID Connect Core 1.0. Cualquier aplicación puede integrar "Iniciar sesión con VaultAuth" del mismo modo que se integraría con Google o GitHub.

---

## Índice

- [Descubrimiento automático](#descubrimiento-automático)
- [Flujo Authorization Code + PKCE](#flujo-authorization-code--pkce)
  - [1. Iniciar autorización](#1-iniciar-autorización-get-oauthauthorize)
  - [2. Intercambiar código por tokens](#2-intercambiar-código-por-tokens-post-oauthtoken)
  - [3. Obtener información del usuario](#3-obtener-información-del-usuario-get-oauthuserinfo)
- [Refresh Token](#refresh-token)
- [Introspección de token](#introspección-de-token)
- [Revocación de token](#revocación-de-token)
- [Gestión de aplicaciones](#gestión-de-aplicaciones)
- [Scopes](#scopes)
- [Métodos de autenticación del cliente](#métodos-de-autenticación-del-cliente)

---

## Descubrimiento automático

| Método | Ruta                                | Descripción                        |
| ------ | ----------------------------------- | ---------------------------------- |
| `GET`  | `/.well-known/openid-configuration` | Documento de descubrimiento OIDC   |
| `GET`  | `/.well-known/jwks.json`            | Conjunto de claves públicas (JWKS) |

### GET `/.well-known/openid-configuration`

Devuelve la configuración del servidor de autorización. Cualquier cliente compatible con OIDC puede autodescubrirse apuntando a esta URL.

**Respuesta:**

```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
  "revocation_endpoint": "http://localhost:3000/oauth/revoke",
  "introspection_endpoint": "http://localhost:3000/oauth/introspect",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "scopes_supported": ["openid", "profile", "email", "notes"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "none"
  ],
  "claims_supported": ["sub", "email", "email_verified", "name"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

---

## Flujo Authorization Code + PKCE

### 1. Iniciar autorización — `GET /oauth/authorize`

El punto de entrada del flujo OAuth. El cliente redirige el navegador del usuario a esta URL.

**Parámetros de consulta:**

| Parámetro               | Requerido                         | Descripción                                      |
| ----------------------- | --------------------------------- | ------------------------------------------------ |
| `response_type`         | Sí                                | Debe ser `code`                                  |
| `client_id`             | Sí                                | ID de la aplicación registrada                   |
| `redirect_uri`          | Sí                                | URI de redirección exactamente como se registró  |
| `scope`                 | No                                | Scopes separados por espacio (defecto: `openid`) |
| `state`                 | Recomendado                       | Valor opaco para prevenir CSRF                   |
| `code_challenge`        | Requerido para clientes públicos  | Hash SHA-256 del `code_verifier` en base64url    |
| `code_challenge_method` | Requerido si hay `code_challenge` | `S256` (recomendado) o `plain`                   |

**Comportamiento:**

- Si el usuario **no está autenticado** en VaultAuth, se redirige a `/login?from=/oauth/authorize?...` preservando todos los parámetros OAuth.
- Si el usuario **está autenticado**, se redirige a la pantalla de consentimiento en el frontend.

**Ejemplo de URL:**

```
http://localhost:3000/oauth/authorize
  ?response_type=code
  &client_id=cmp5z4qvh0003n14uczcndcyq
  &redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fapi%2Fauth%2Fcallback%2Fvaultauth
  &scope=openid+profile+email
  &state=abc123
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

**Respuesta exitosa (después del consent):**

```
HTTP/1.1 302 Found
Location: http://localhost:3002/api/auth/callback/vaultauth?code=<auth_code>&state=abc123
```

**Códigos de error:**

| Código | Descripción                                                            |
| ------ | ---------------------------------------------------------------------- |
| `400`  | `client_id` inválido, `redirect_uri` no registrada, scope no permitido |
| `403`  | El usuario de la sesión no coincide con el solicitante                 |

---

### 2. Intercambiar código por tokens — `POST /oauth/token`

Intercambia el `authorization_code` por `access_token` y `refresh_token`.

**Límite de tasa:** 20 req/min por IP.

**Content-Type:** `application/x-www-form-urlencoded` o `application/json`

**Parámetros:**

| Parámetro       | Requerido   | Descripción                                             |
| --------------- | ----------- | ------------------------------------------------------- |
| `grant_type`    | Sí          | `authorization_code`                                    |
| `code`          | Sí          | Código recibido en el callback                          |
| `redirect_uri`  | Sí          | Debe coincidir exactamente con el usado en `/authorize` |
| `client_id`     | Sí\*        | ID del cliente                                          |
| `client_secret` | Condicional | Secreto del cliente (clientes confidenciales)           |
| `code_verifier` | Condicional | Verificador PKCE (clientes públicos)                    |

\*`client_id` puede enviarse en el body (`client_secret_post`) o en el encabezado `Authorization: Basic` (`client_secret_basic`).

**Ejemplo con `client_secret_post`:**

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123def456...
&redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fapi%2Fauth%2Fcallback%2Fvaultauth
&client_id=cmp5z4qvh0003n14uczcndcyq
&client_secret=3e042f60ee662...
```

**Ejemplo con `client_secret_basic`:**

```http
POST /oauth/token HTTP/1.1
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123def456...
&redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fapi%2Fauth%2Fcallback%2Fvaultauth
```

**Ejemplo con PKCE (cliente público):**

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123def456...
&redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fapi%2Fauth%2Fcallback%2Fvaultauth
&client_id=cmp5z4qvh0003n14uczcndcyq
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Respuesta exitosa:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "a8f4b2c1d9e3f7...",
  "scope": "openid profile email"
}
```

| Campo           | Descripción                                                                               |
| --------------- | ----------------------------------------------------------------------------------------- |
| `access_token`  | JWT HS256, TTL 1 hora. Claims: `sub`, `client_id`, `scope`, `jti`, `type: "oauth_access"` |
| `token_type`    | Siempre `Bearer`                                                                          |
| `expires_in`    | Segundos hasta la expiración del `access_token`                                           |
| `refresh_token` | Token opaco de 96 bytes (hex), sin expiración fija; revocado en el siguiente refresh      |
| `scope`         | Scopes concedidos separados por espacio                                                   |

> **Nota:** El endpoint NO devuelve `id_token`. Para obtener los claims del usuario, usa `/oauth/userinfo` con el `access_token`.

---

### 3. Obtener información del usuario — `GET /oauth/userinfo`

Devuelve los claims del usuario según los scopes concedidos. Compatible con OIDC Core § 5.3.

**Autenticación:** `Authorization: Bearer <access_token>`

**Ejemplo:**

```http
GET /oauth/userinfo HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Respuesta (scopes `openid profile email`):**

```json
{
  "sub": "clv3a2x1h0000n1uqabcd1234",
  "name": "Juan García",
  "email": "juan@ejemplo.com",
  "email_verified": true
}
```

**Claims por scope:**

| Scope     | Claims incluidos                                              |
| --------- | ------------------------------------------------------------- |
| `openid`  | `sub` (siempre presente)                                      |
| `profile` | `name`                                                        |
| `email`   | `email`, `email_verified`                                     |
| `notes`   | _(sin claims adicionales; habilita acceso a la API de notas)_ |

**Errores:**

| Código | Descripción                         |
| ------ | ----------------------------------- |
| `401`  | Token inválido, expirado o revocado |

---

## Refresh Token

**`POST /oauth/token`** con `grant_type=refresh_token`

| Parámetro       | Requerido   | Descripción                              |
| --------------- | ----------- | ---------------------------------------- |
| `grant_type`    | Sí          | `refresh_token`                          |
| `refresh_token` | Sí          | Token de refresco obtenido anteriormente |
| `client_id`     | Sí          | ID del cliente                           |
| `client_secret` | Condicional | Requerido para clientes confidenciales   |

**Comportamiento:** el `refresh_token` anterior queda **revocado** y se emiten nuevos `access_token` y `refresh_token`.

**Respuesta:** idéntica a la del intercambio de código.

---

## Introspección de token

**`POST /oauth/introspect`** — RFC 7662

Permite al cliente verificar si un token es válido.

**Body:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_id": "cmp5z4qvh0003n14uczcndcyq",
  "client_secret": "3e042f60ee662..."
}
```

**Respuesta (token activo):**

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "cmp5z4qvh0003n14uczcndcyq",
  "sub": "clv3a2x1h0000n1uqabcd1234",
  "exp": 1715700000,
  "username": "juan@ejemplo.com"
}
```

**Respuesta (token inactivo/expirado):**

```json
{ "active": false }
```

---

## Revocación de token

**`POST /oauth/revoke`** — RFC 7009

Revoca un `access_token` o `refresh_token`. Siempre devuelve HTTP 200 (idempotente).

**Body:**

```json
{
  "token": "a8f4b2c1d9e3f7...",
  "client_id": "cmp5z4qvh0003n14uczcndcyq",
  "client_secret": "3e042f60ee662..."
}
```

---

## Gestión de aplicaciones

Estos endpoints requieren autenticación como usuario de VaultAuth (sesión o JWT).

| Método   | Ruta                                | Descripción                     | Guards              |
| -------- | ----------------------------------- | ------------------------------- | ------------------- |
| `POST`   | `/oauth/apps`                       | Registrar nueva aplicación      | `HybridAuth + CSRF` |
| `GET`    | `/oauth/apps`                       | Listar aplicaciones del usuario | `HybridAuth`        |
| `DELETE` | `/oauth/apps/:id`                   | Eliminar aplicación             | `HybridAuth + CSRF` |
| `POST`   | `/oauth/apps/:id/regenerate-secret` | Regenerar `client_secret`       | `HybridAuth + CSRF` |

### POST `/oauth/apps`

**Body:**

```json
{
  "name": "Mi Aplicación",
  "description": "Descripción opcional",
  "redirectUris": ["http://localhost:3002/api/auth/callback/vaultauth"],
  "scopes": ["openid", "profile", "email"]
}
```

**Respuesta:**

```json
{
  "app": {
    "id": "clv3a2x1h0000n1uqabcd1234",
    "clientId": "cmp5z4qvh0003n14uczcndcyq",
    "name": "Mi Aplicación",
    "description": "Descripción opcional",
    "redirectUris": ["http://localhost:3002/api/auth/callback/vaultauth"],
    "scopes": ["openid", "profile", "email"],
    "userId": "...",
    "createdAt": "2026-05-14T00:00:00.000Z"
  },
  "plainSecret": "3e042f60ee662ce4a48cb8a95a7c5970adfee8fa6a3a8ca9544e2c977e4974d3"
}
```

> **Importante:** `plainSecret` se devuelve **una sola vez**. Almacénalo de forma segura; no se puede recuperar después.

---

## Scopes

| Scope     | Descripción                                 | Claims en userinfo        |
| --------- | ------------------------------------------- | ------------------------- |
| `openid`  | Identidad básica. **Siempre requerido**     | `sub`                     |
| `profile` | Nombre del usuario                          | `name`                    |
| `email`   | Dirección de email y estado de verificación | `email`, `email_verified` |
| `notes`   | Acceso a la API de notas del usuario        | _(ninguno adicional)_     |

---

## Métodos de autenticación del cliente

| Método                | Descripción                                                            |
| --------------------- | ---------------------------------------------------------------------- |
| `client_secret_post`  | `client_id` y `client_secret` en el body de la petición                |
| `client_secret_basic` | Credenciales en el encabezado `Authorization: Basic base64(id:secret)` |
| `none`                | Sin secreto — solo PKCE (`code_verifier` obligatorio)                  |

---

## Notas de seguridad

- Los `authorization_code` expiran en **10 minutos** y son de un solo uso.
- Los `access_token` expiran en **1 hora**.
- Los `refresh_token` no tienen TTL fijo pero quedan revocados en cada uso (rotación).
- Las `redirect_uri` se validan con coincidencia **exacta** (sin prefijo ni glob).
- Rate limit de **20 req/min** en `/oauth/authorize` y `/oauth/token`.
- El endpoint `/oauth/token` rechaza peticiones sin `client_id` identificable.
