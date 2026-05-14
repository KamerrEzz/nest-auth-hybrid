#language: es
# ==============================================================================
# VaultAuth — Especificaciones BDD: Autenticación
# Dominio: Registro, Login, Bloqueo de cuenta, Cambio de contraseña
# ==============================================================================

Feature: Autenticación de usuarios
  Como usuario del sistema VaultAuth
  Quiero poder registrarme e iniciar sesión de forma segura
  Para acceder a mis recursos protegidos y aplicaciones OAuth

  # ============================================================================
  # REGISTRO
  # ============================================================================

  @auth @registro @happy-path
  Scenario: Registro exitoso con datos válidos
    Given que el servidor está en línea
    And no existe ningún usuario con email "nuevo@ejemplo.com"
    When envío POST /auth/register con:
      | campo    | valor              |
      | email    | nuevo@ejemplo.com  |
      | password | Segura123!         |
      | name     | Usuario Nuevo      |
    Then la respuesta tiene status 201
    And el cuerpo contiene un campo "id"
    And el cuerpo contiene un campo "email" con valor "nuevo@ejemplo.com"
    And el cuerpo NO contiene el campo "password"

  @auth @registro @error-path
  Scenario: Registro falla con email duplicado
    Given que existe un usuario con email "existente@ejemplo.com"
    When envío POST /auth/register con:
      | campo    | valor                |
      | email    | existente@ejemplo.com |
      | password | OtraPassword1!       |
      | name     | Otro Usuario         |
    Then la respuesta tiene status 409
    And el cuerpo contiene un campo "message" con texto "already exists" o similar

  @auth @registro @error-path @validacion
  Scenario Outline: Registro falla con contraseña débil
    Given que el servidor está en línea
    When envío POST /auth/register con:
      | campo    | valor         |
      | email    | test@test.com |
      | password | <password>    |
      | name     | Test User     |
    Then la respuesta tiene status 400
    And el cuerpo contiene información de validación indicando "<razon>"

    Examples:
      | password | razon                        |
      | 123      | mínimo 8 caracteres          |
      | abc      | mínimo 8 caracteres          |
      | 1234567  | mínimo 8 caracteres          |
      |          | campo requerido              |

  @auth @registro @error-path @validacion
  Scenario Outline: Registro falla con formato de email inválido
    Given que el servidor está en línea
    When envío POST /auth/register con:
      | campo    | valor         |
      | email    | <email>       |
      | password | Password123!  |
      | name     | Test User     |
    Then la respuesta tiene status 400
    And el cuerpo indica que el campo "email" no es válido

    Examples:
      | email           |
      | no-es-un-email  |
      | @sindominio.com |
      | sin-arroba.com  |
      | user@           |

  # ============================================================================
  # LOGIN SIN 2FA
  # ============================================================================

  @auth @login @happy-path
  Scenario: Login exitoso devuelve cookie de sesión y access token
    Given que existe un usuario con email "usuario@ejemplo.com" y password "MiPassword1!"
    And el usuario NO tiene 2FA habilitado
    And la cuenta NO está bloqueada
    When envío POST /auth/login con:
      | campo    | valor               |
      | email    | usuario@ejemplo.com |
      | password | MiPassword1!        |
    Then la respuesta tiene status 200
    And la respuesta incluye una cookie "sessionId" con HttpOnly y SameSite=Strict
    And el cuerpo contiene un campo "access_token"
    And el cuerpo contiene un campo "user" con sub-campos "id", "email"
    And el cuerpo NO contiene "requiresOtp"

  @auth @login @error-path @security
  Scenario: Login falla con contraseña incorrecta
    Given que existe un usuario con email "usuario@ejemplo.com" y password "MiPassword1!"
    And la cuenta NO está bloqueada
    When envío POST /auth/login con:
      | campo    | valor               |
      | email    | usuario@ejemplo.com |
      | password | ContraseñaErronea1! |
    Then la respuesta tiene status 401
    And el cuerpo contiene un campo "message" con texto de error de credenciales

  @auth @login @error-path
  Scenario: Login falla con email inexistente
    Given que no existe ningún usuario con email "fantasma@ejemplo.com"
    When envío POST /auth/login con:
      | campo    | valor                 |
      | email    | fantasma@ejemplo.com  |
      | password | CualquierPassword1!   |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error genérico de credenciales
    And el mensaje NO revela si el email existe o no

  @auth @login @security @bloqueo
  Scenario: Login en cuenta bloqueada devuelve error 429 incluso con credenciales correctas
    Given que existe un usuario con email "bloqueado@ejemplo.com" y password "MiPassword1!"
    And la clave Redis "lockout:bloqueado@ejemplo.com" existe con TTL mayor a 0
    When envío POST /auth/login con:
      | campo    | valor                  |
      | email    | bloqueado@ejemplo.com  |
      | password | MiPassword1!           |
    Then la respuesta tiene status 429
    And el cuerpo contiene un campo "message" que indica que la cuenta está bloqueada
    And el cuerpo contiene información sobre el tiempo de espera

  # ============================================================================
  # BLOQUEO DE CUENTA (Account Lockout)
  # ============================================================================

  @auth @bloqueo @security
  Scenario: 5 intentos fallidos consecutivos bloquean la cuenta por 15 minutos
    Given que existe un usuario con email "victima@ejemplo.com" y password "CorrectaPass1!"
    And la cuenta NO está bloqueada
    When realizo 5 intentos de login con password incorrecta para "victima@ejemplo.com"
    Then el 5to intento responde con status 401
    And la clave Redis "lockout:victima@ejemplo.com" existe con TTL aproximado de 900 segundos
    When envío POST /auth/login con credenciales correctas de "victima@ejemplo.com"
    Then la respuesta tiene status 429
    And el cuerpo indica que la cuenta está bloqueada

  @auth @bloqueo @security @happy-path
  Scenario: Login exitoso antes de 5 fallos reinicia el contador de intentos
    Given que existe un usuario con email "usuario@ejemplo.com" y password "CorrectaPass1!"
    And la cuenta NO está bloqueada
    When realizo 3 intentos de login con password incorrecta para "usuario@ejemplo.com"
    And envío POST /auth/login con credenciales correctas de "usuario@ejemplo.com"
    Then la respuesta tiene status 200
    And la clave Redis de intentos fallidos para "usuario@ejemplo.com" ya no existe o es 0

  @auth @bloqueo @security
  Scenario: Cuenta bloqueada rechaza login aunque la contraseña sea correcta
    Given que existe un usuario con email "bloqueado2@ejemplo.com" y password "CorrectaPass1!"
    And la clave Redis "lockout:bloqueado2@ejemplo.com" existe (cuenta bloqueada)
    When envío POST /auth/login con:
      | campo    | valor                   |
      | email    | bloqueado2@ejemplo.com  |
      | password | CorrectaPass1!          |
    Then la respuesta tiene status 429
    And NO se crea ninguna sesión nueva

  # ============================================================================
  # CAMBIO DE CONTRASEÑA
  # ============================================================================

  @auth @password @happy-path
  Scenario: Cambio de contraseña exitoso cuando el usuario está autenticado
    Given que existe un usuario con email "usuario@ejemplo.com" y password "ViejaPass1!"
    And el usuario tiene una sesión activa (cookie sessionId válida)
    When envío POST /auth/change-password con:
      | campo           | valor         |
      | currentPassword | ViejaPass1!   |
      | newPassword     | NuevaPass99!  |
    Then la respuesta tiene status 200
    And el cuerpo contiene un mensaje de confirmación
    When envío POST /auth/login con:
      | campo    | valor               |
      | email    | usuario@ejemplo.com |
      | password | ViejaPass1!         |
    Then la respuesta tiene status 401

  @auth @password @error-path @security
  Scenario: Cambio de contraseña falla cuando la contraseña actual es incorrecta
    Given que existe un usuario con email "usuario@ejemplo.com" y password "CorrectaPass1!"
    And el usuario tiene una sesión activa (cookie sessionId válida)
    When envío POST /auth/change-password con:
      | campo           | valor          |
      | currentPassword | ContraseñaMal! |
      | newPassword     | NuevaPass99!   |
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error indicando contraseña incorrecta
    And la contraseña del usuario NO ha cambiado

  @auth @password @error-path
  Scenario: Cambio de contraseña falla si el usuario no está autenticado
    Given que no hay sesión activa ni token Bearer
    When envío POST /auth/change-password con:
      | campo           | valor         |
      | currentPassword | CualquierPass |
      | newPassword     | NuevaPass99!  |
    Then la respuesta tiene status 401
