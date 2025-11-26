# Documentación de Endpoints de Autenticación

Este documento detalla los endpoints disponibles en el módulo `src/features/auth`.

## Resumen de Endpoints

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| POST | `/auth/register` | Registra un nuevo usuario. |
| POST | `/auth/login` | Inicia sesión con credenciales. |
| POST | `/auth/verify-otp` | Verifica el código OTP para 2FA. |
| POST | `/auth/enable-2fa` | Inicia el proceso de habilitación de 2FA. |
| POST | `/auth/verify-2fa` | Verifica el código para confirmar 2FA. |
| GET | `/auth/2fa/status` | Obtiene el estado de 2FA del usuario. |
| POST | `/auth/disable-2fa` | Deshabilita 2FA. |
| POST | `/auth/2fa/cancel` | Cancela el proceso de configuración de 2FA. |
| GET | `/auth/csrf` | Obtiene un token CSRF. |
| POST | `/auth/change-password` | Cambia la contraseña del usuario. |
| POST | `/auth/refresh` | Refresca el token de acceso. |
| GET | `/auth/me` | Obtiene la información del usuario actual. |
| POST | `/auth/logout` | Cierra la sesión actual. |
| GET | `/auth/sessions` | Lista las sesiones activas del usuario. |
| DELETE | `/auth/sessions` | Revoca todas las sesiones del usuario. |
| DELETE | `/auth/sessions/:id` | Revoca una sesión específica. |
| DELETE | `/auth/sessions/others` | Revoca todas las sesiones excepto la actual. |
| GET | `/auth/google` | Inicia autenticación con Google. |
| GET | `/auth/google/callback` | Callback de autenticación con Google. |
| GET | `/auth/discord` | Inicia autenticación con Discord. |
| GET | `/auth/discord/callback` | Callback de autenticación con Discord. |

---

## Detalle de Endpoints

### 1. Registrar Usuario

**Endpoint:** `POST /auth/register`

**Descripción:** Crea una nueva cuenta de usuario.

**Request Body (`RegisterDto`):**

| Campo | Tipo | Validaciones | Descripción |
| :--- | :--- | :--- | :--- |
| `email` | string | `@IsEmail()` | Correo electrónico del usuario. |
| `password` | string | `@IsString()`, `@MinLength(8)`, `@Matches(...)` | Contraseña. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial. |
| `name` | string | `@IsString()` | (Opcional) Nombre del usuario. |

**Response (`RegisterResponseDto`):**

```json
{
  "message": "Registration successful",
  "user": {
    "id": "string",
    "email": "string",
    "name": "string",
    "createdAt": "Date"
  },
  "accessToken": "string",
  "refreshToken": "string"
}
```

**Cookies:**
- `sessionId`: HttpOnly, Secure (prod), SameSite: Strict
- `csrfToken`: HttpOnly: false, Secure (prod), SameSite: Strict

---

### 2. Iniciar Sesión

**Endpoint:** `POST /auth/login`

**Descripción:** Autentica a un usuario con correo y contraseña.

**Request Body (`LoginDto`):**

| Campo | Tipo | Validaciones | Descripción |
| :--- | :--- | :--- | :--- |
| `email` | string | `@IsEmail()` | Correo electrónico. |
| `password` | string | `@IsString()`, `@MinLength(8)` | Contraseña. |

**Response:**

*Caso Exitoso (`AuthResponseDto`):*
```json
{
  "accessToken": "string",
  "refreshToken": "string",
  "user": {
    "id": "string",
    "email": "string",
    "name": "string",
    "createdAt": "Date"
  },
  "expiresIn": number
}
```

*Caso 2FA Requerido:*
```json
{
  "requiresOtp": true,
  "tempToken": "string"
}
```

**Cookies (Caso Exitoso):**
- `sessionId`
- `csrfToken`

---

### 3. Verificar OTP (Login 2FA)

**Endpoint:** `POST /auth/verify-otp`

**Descripción:** Completa el inicio de sesión verificando el código OTP cuando el usuario tiene 2FA habilitado.

**Headers:**
- Requiere autenticación previa (token temporal o sesión parcial, manejado por `AuthGuard('twofa')`).

**Response (`AuthResponseDto`):**
Misma estructura que `POST /auth/login` (Caso Exitoso).

---

### 4. Habilitar 2FA

**Endpoint:** `POST /auth/enable-2fa`

**Descripción:** Genera un secreto TOTP para configurar 2FA.

**Response:**
```json
{
  "secret": "string",
  "otpauthUrl": "string"
}
```
*(Nota: La respuesta exacta depende de `auth.service.ts`, se infiere estructura común)*

---

### 5. Verificar Configuración 2FA

**Endpoint:** `POST /auth/verify-2fa`

**Descripción:** Confirma la habilitación de 2FA validando un código generado por la app autenticadora.

**Request Body:**
```json
{
  "code": "string"
}
```

**Response:**
`boolean` (Retorna el resultado de la verificación).

---

### 6. Estado de 2FA

**Endpoint:** `GET /auth/2fa/status`

**Descripción:** Devuelve el estado actual de la autenticación de dos factores para el usuario.

**Response:**
```json
{
  "enabled": boolean,
  "hasSecret": boolean,
  "backupCount": number
}
```

---

### 7. Deshabilitar 2FA

**Endpoint:** `POST /auth/disable-2fa`

**Descripción:** Desactiva la autenticación de dos factores.

**Request Body:**
```json
{
  "totpCode": "string", // Opcional
  "backupCode": "string" // Opcional
}
```

**Response:**
`boolean`

---

### 8. Cancelar Configuración 2FA

**Endpoint:** `POST /auth/2fa/cancel`

**Descripción:** Cancela el proceso de configuración de 2FA si no se ha completado.

**Response:**
`boolean`

---

### 9. Obtener CSRF Token

**Endpoint:** `GET /auth/csrf`

**Descripción:** Obtiene un token CSRF para proteger peticiones mutantes.

**Response:**
```json
{
  "csrfToken": "string"
}
```
**Cookies:** Establece la cookie `csrfToken`.

---

### 10. Cambiar Contraseña

**Endpoint:** `POST /auth/change-password`

**Descripción:** Permite al usuario cambiar su contraseña actual.

**Request Body (`ChangePasswordDto`):**

| Campo | Tipo | Validaciones | Descripción |
| :--- | :--- | :--- | :--- |
| `currentPassword` | string | `@IsString()`, `@MinLength(8)` | Contraseña actual. |
| `newPassword` | string | `@IsString()`, `@MinLength(8)` | Nueva contraseña. |
| `totpCode` | string | `@IsOptional()`, `@IsString()` | Código 2FA si está habilitado. |

**Response:**
`boolean` (o resultado de la operación).

---

### 11. Refrescar Token

**Endpoint:** `POST /auth/refresh`

**Descripción:** Obtiene un nuevo access token usando un refresh token.

**Request Body (`RefreshTokenDto`):**

| Campo | Tipo | Validaciones | Descripción |
| :--- | :--- | :--- | :--- |
| `refreshToken` | string | `@IsString()` | El refresh token. |

**Response:**
`AuthResponseDto` (o similar, depende de la implementación del servicio).

---

### 12. Obtener Usuario Actual

**Endpoint:** `GET /auth/me`

**Descripción:** Devuelve la información del perfil del usuario autenticado.

**Response (`UserResponseDto`):**
```json
{
  "id": "string",
  "email": "string",
  "name": "string",
  "createdAt": "Date"
}
```
*(Nota: Campos sensibles como password, totpSecret, etc., son excluidos)*

---

### 13. Cerrar Sesión

**Endpoint:** `POST /auth/logout`

**Descripción:** Cierra la sesión del usuario y limpia las cookies de sesión.

**Response:**
```json
{
  "ok": true
}
```

---

### 14. Listar Sesiones

**Endpoint:** `GET /auth/sessions`

**Descripción:** Lista todas las sesiones activas del usuario.

**Response:**
```json
{
  "currentId": "string",
  "items": [
    {
      "id": "string",
      "userId": "string",
      "ipAddress": "string",
      "userAgent": "string",
      "location": "string",
      "expiresAt": number,
      "lastActive": number
    }
  ]
}
```

---

### 15. Revocar Todas las Sesiones

**Endpoint:** `DELETE /auth/sessions`

**Descripción:** Cierra todas las sesiones activas del usuario.

**Response:**
```json
{
  "ok": true
}
```

---

### 16. Revocar Sesión Específica

**Endpoint:** `DELETE /auth/sessions/:id`

**Descripción:** Cierra una sesión específica por su ID.

**Parámetros:**
- `id`: ID de la sesión a revocar.

**Response:**
```json
{
  "ok": true
}
```

---

### 17. Revocar Otras Sesiones

**Endpoint:** `DELETE /auth/sessions/others`

**Descripción:** Cierra todas las sesiones excepto la actual.

**Response:**
```json
{
  "ok": true
}
```

---

### 18-21. OAuth (Google / Discord)

**Endpoints:**
- `GET /auth/google`
- `GET /auth/google/callback`
- `GET /auth/discord`
- `GET /auth/discord/callback`

**Descripción:** Manejan el flujo de autenticación OAuth2.

**Response (Callbacks):**
Retornan `AuthResponseDto` (éxito) o `{ requiresOtp: true, tempToken: string }` (si 2FA es requerido), similar al login normal.
