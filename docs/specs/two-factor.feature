#language: es
# ==============================================================================
# VaultAuth — Especificaciones BDD: Autenticación de Dos Factores (2FA / TOTP)
# Dominio: Configuración 2FA, flujo de login con OTP, estado y desactivación
# Compatible con Google Authenticator (RFC 6238 TOTP)
# ==============================================================================

Feature: Autenticación de dos factores (2FA TOTP)
  Como usuario preocupado por la seguridad
  Quiero activar la autenticación de dos factores con TOTP
  Para proteger mi cuenta incluso si mi contraseña es comprometida

  Background:
    Given que el servidor está en línea
    And existe un usuario con email "usuario2fa@ejemplo.com" y password "SecurePass1!"

  # ============================================================================
  # CONFIGURACIÓN DE 2FA (Setup)
  # ============================================================================

  @2fa @setup @happy-path
  Scenario: Habilitar 2FA devuelve QR code y secret
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario NO tiene 2FA habilitado
    When envío POST /auth/enable-2fa
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "qrCodeUrl" con una URL de imagen (data URI o HTTPS)
    And el cuerpo contiene un campo "secret" con una cadena base32 de al menos 16 caracteres
    And el estado de 2FA del usuario en la base de datos es "pendiente" (secret guardado, no activado)

  @2fa @setup @happy-path
  Scenario: Verificar configuración de 2FA con código TOTP válido activa el 2FA
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene un secret TOTP pendiente de verificación
    When envío POST /auth/verify-2fa con:
      | campo | valor              |
      | code  | <codigo_totp_valido> |
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "message" de confirmación
    And el campo "twoFactorEnabled" del usuario en la base de datos es true
    And el secret TOTP queda almacenado de forma permanente

  @2fa @setup @error-path
  Scenario: Verificar configuración de 2FA con código TOTP inválido falla la activación
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene un secret TOTP pendiente de verificación
    When envío POST /auth/verify-2fa con:
      | campo | valor   |
      | code  | 000000  |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error indicando código inválido
    And el campo "twoFactorEnabled" del usuario en la base de datos sigue siendo false

  @2fa @setup @error-path @validacion
  Scenario Outline: Verificar 2FA con formatos de código inválidos
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene un secret TOTP pendiente de verificación
    When envío POST /auth/verify-2fa con código "<codigo>"
    Then la respuesta tiene status <status>
    And el cuerpo contiene indicación de error

    Examples:
      | codigo    | status |
      | 12345     | 400    |
      | 1234567   | 400    |
      | abcdef    | 400    |
      |           | 400    |

  @2fa @setup @happy-path
  Scenario: Cancelar la configuración de 2FA en progreso
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene un secret TOTP pendiente de verificación
    When envío POST /auth/2fa/cancel
    Then la respuesta tiene status 200
    And el secret TOTP pendiente es eliminado de la base de datos
    And el campo "twoFactorEnabled" del usuario en la base de datos sigue siendo false

  @2fa @setup @error-path
  Scenario: Intentar activar 2FA sin estar autenticado falla
    Given que no hay sesión activa ni token Bearer
    When envío POST /auth/enable-2fa
    Then la respuesta tiene status 401

  # ============================================================================
  # FLUJO DE LOGIN CON 2FA
  # ============================================================================

  @2fa @login @happy-path
  Scenario: Login en cuenta con 2FA habilitado devuelve requiresOtp y tempToken
    Given el usuario "usuario2fa@ejemplo.com" tiene 2FA habilitado
    When envío POST /auth/login con:
      | campo    | valor                  |
      | email    | usuario2fa@ejemplo.com |
      | password | SecurePass1!           |
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "requiresOtp" con valor true
    And el cuerpo contiene un campo "tempToken" (JWT o token opaco temporal)
    And la respuesta NO incluye cookie "sessionId"
    And la respuesta NO incluye campo "access_token" definitivo

  @2fa @login @happy-path
  Scenario: Verificar OTP con código válido y tempToken válido crea la sesión
    Given el usuario "usuario2fa@ejemplo.com" tiene 2FA habilitado
    And tengo un "tempToken" válido obtenido tras el login inicial
    When envío POST /auth/verify-otp con:
      | campo     | valor                |
      | tempToken | <tempToken_valido>   |
      | code      | <codigo_totp_valido> |
    Then la respuesta tiene status 200
    And la respuesta incluye una cookie "sessionId" con HttpOnly y SameSite=Strict
    And el cuerpo contiene un campo "access_token"
    And el cuerpo contiene un campo "user" con sub-campos "id", "email"
    And el tempToken queda invalidado (no puede reutilizarse)

  @2fa @login @error-path @security
  Scenario: Verificar OTP con código TOTP inválido devuelve 401
    Given el usuario "usuario2fa@ejemplo.com" tiene 2FA habilitado
    And tengo un "tempToken" válido obtenido tras el login inicial
    When envío POST /auth/verify-otp con:
      | campo     | valor              |
      | tempToken | <tempToken_valido> |
      | code      | 000000             |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error indicando código OTP inválido
    And NO se crea ninguna sesión

  @2fa @login @error-path @security
  Scenario Outline: Verificar OTP con tempToken inválido o expirado devuelve 401
    Given el usuario "usuario2fa@ejemplo.com" tiene 2FA habilitado
    When envío POST /auth/verify-otp con:
      | campo     | valor                |
      | tempToken | <tempToken>          |
      | code      | <codigo_totp_valido> |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error indicando "<razon>"

    Examples:
      | tempToken                     | razon                  |
      | token_completamente_falso     | token inválido         |
      | token_expirado_hace_10_min    | token expirado         |
      |                               | token requerido        |

  @2fa @login @security
  Scenario: El tempToken no puede usarse más de una vez
    Given el usuario "usuario2fa@ejemplo.com" tiene 2FA habilitado
    And tengo un "tempToken" válido obtenido tras el login inicial
    And ya usé el tempToken exitosamente para crear una sesión
    When envío POST /auth/verify-otp con el mismo tempToken y un código TOTP válido
    Then la respuesta tiene status 401

  # ============================================================================
  # ESTADO Y DESACTIVACIÓN DE 2FA
  # ============================================================================

  @2fa @estado @happy-path
  Scenario: GET /auth/2fa/status devuelve enabled:true cuando 2FA está activo
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene 2FA habilitado
    When envío GET /auth/2fa/status
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "enabled" con valor true

  @2fa @estado @happy-path
  Scenario: GET /auth/2fa/status devuelve enabled:false cuando 2FA NO está activo
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario NO tiene 2FA habilitado
    When envío GET /auth/2fa/status
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "enabled" con valor false

  @2fa @estado @error-path
  Scenario: GET /auth/2fa/status sin autenticación devuelve 401
    Given que no hay sesión activa ni token Bearer
    When envío GET /auth/2fa/status
    Then la respuesta tiene status 401

  @2fa @disable @happy-path
  Scenario: Deshabilitar 2FA con contraseña correcta desactiva el 2FA
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene 2FA habilitado
    When envío POST /auth/disable-2fa con:
      | campo    | valor        |
      | password | SecurePass1! |
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "message" de confirmación
    And el campo "twoFactorEnabled" del usuario en la base de datos es false
    And el secret TOTP del usuario es eliminado de la base de datos

  @2fa @disable @error-path @security
  Scenario: Deshabilitar 2FA con contraseña incorrecta devuelve 401
    Given el usuario "usuario2fa@ejemplo.com" está autenticado con sesión válida
    And el usuario tiene 2FA habilitado
    When envío POST /auth/disable-2fa con:
      | campo    | valor             |
      | password | ContraseñaMala99! |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error indicando contraseña incorrecta
    And el campo "twoFactorEnabled" del usuario en la base de datos sigue siendo true

  @2fa @disable @error-path
  Scenario: Deshabilitar 2FA sin autenticación devuelve 401
    Given que no hay sesión activa ni token Bearer
    When envío POST /auth/disable-2fa con:
      | campo    | valor        |
      | password | SecurePass1! |
    Then la respuesta tiene status 401
