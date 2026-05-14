#language: es
# ==============================================================================
# VaultAuth — Especificaciones BDD: Gestión de Sesiones
# Dominio: Ciclo de vida de sesión, listado/revocación, validación, JWT Bearer
# Sesiones almacenadas en Redis con TTL deslizante (sliding window) de 7 días
# ==============================================================================

Feature: Gestión de sesiones de usuario
  Como usuario autenticado
  Quiero que mis sesiones sean creadas, mantenidas y revocadas correctamente
  Para tener control total sobre el acceso a mi cuenta desde múltiples dispositivos

  Background:
    Given que el servidor está en línea
    And existe un usuario con email "sesion@ejemplo.com" y password "SesionPass1!"
    And el usuario NO tiene 2FA habilitado

  # ============================================================================
  # CICLO DE VIDA DE LA SESIÓN
  # ============================================================================

  @sesion @ciclo-de-vida @happy-path
  Scenario: Login crea una sesión almacenada en Redis con cookie sessionId
    Given la cuenta NO está bloqueada
    When envío POST /auth/login con:
      | campo    | valor               |
      | email    | sesion@ejemplo.com  |
      | password | SesionPass1!        |
    Then la respuesta tiene status 200
    And la respuesta incluye una cookie "sessionId" con atributos HttpOnly y SameSite=Strict
    And la clave Redis "session:<sessionId>" existe con TTL aproximado de 604800 segundos (7 días)
    And la sesión en Redis contiene el campo "userId" del usuario

  @sesion @ciclo-de-vida @happy-path
  Scenario: GET /auth/me con sesión válida devuelve datos del usuario
    Given el usuario "sesion@ejemplo.com" tiene una sesión activa (cookie sessionId válida)
    When envío GET /auth/me con la cookie de sesión
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "id"
    And el cuerpo contiene un campo "email" con valor "sesion@ejemplo.com"
    And el cuerpo NO contiene el campo "password"
    And el cuerpo NO contiene el campo "twoFactorSecret"

  @sesion @ciclo-de-vida @error-path
  Scenario: GET /auth/me sin sesión devuelve 401
    Given que no hay sesión activa ni token Bearer
    When envío GET /auth/me
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error de no autorizado

  @sesion @ciclo-de-vida @happy-path
  Scenario: POST /auth/logout elimina la sesión de Redis y limpia la cookie
    Given el usuario "sesion@ejemplo.com" tiene una sesión activa (cookie sessionId válida)
    And la clave Redis "session:<sessionId>" existe
    When envío POST /auth/logout con la cookie de sesión
    Then la respuesta tiene status 200
    And la clave Redis "session:<sessionId>" ya NO existe
    And la respuesta incluye una directiva Set-Cookie que expira la cookie "sessionId"
    When envío GET /auth/me con la misma cookie sessionId
    Then la respuesta tiene status 401

  # ============================================================================
  # GESTIÓN DE SESIONES MÚLTIPLES
  # ============================================================================

  @sesion @gestion @happy-path
  Scenario: GET /auth/sessions lista todas las sesiones activas del usuario
    Given el usuario "sesion@ejemplo.com" tiene 3 sesiones activas en distintos dispositivos
    And estoy usando la sesión número 1
    When envío GET /auth/sessions con la cookie de sesión activa
    Then la respuesta tiene status 200
    And el cuerpo es un array con 3 elementos
    And cada elemento contiene los campos "id", "createdAt", "lastActivity"
    And uno de los elementos tiene un indicador "isCurrent: true"

  @sesion @gestion @happy-path
  Scenario: DELETE /auth/sessions/:id revoca una sesión específica
    Given el usuario "sesion@ejemplo.com" tiene 2 sesiones activas
    And estoy usando la sesión "sesion-actual"
    And existe una sesión con id "sesion-otra"
    When envío DELETE /auth/sessions/sesion-otra con la cookie de sesión actual
    Then la respuesta tiene status 200
    And la clave Redis de "sesion-otra" ya NO existe
    And mi sesión actual "sesion-actual" sigue activa

  @sesion @gestion @happy-path
  Scenario: DELETE /auth/sessions/others revoca todas las sesiones excepto la actual
    Given el usuario "sesion@ejemplo.com" tiene 4 sesiones activas
    And estoy usando la sesión "sesion-actual"
    When envío DELETE /auth/sessions/others con la cookie de sesión actual
    Then la respuesta tiene status 200
    And todas las claves Redis de las otras 3 sesiones ya NO existen
    And la sesión "sesion-actual" sigue activa
    And GET /auth/sessions devuelve exactamente 1 sesión

  @sesion @gestion @happy-path
  Scenario: DELETE /auth/sessions revoca todas las sesiones incluyendo la actual
    Given el usuario "sesion@ejemplo.com" tiene 3 sesiones activas
    And estoy usando la sesión "sesion-actual"
    When envío DELETE /auth/sessions con la cookie de sesión actual
    Then la respuesta tiene status 200
    And todas las claves Redis de las 3 sesiones ya NO existen
    When envío GET /auth/me con la cookie "sesion-actual"
    Then la respuesta tiene status 401

  @sesion @gestion @error-path @security
  Scenario: Intentar revocar la sesión de otro usuario devuelve 404 o 403
    Given el usuario "sesion@ejemplo.com" tiene una sesión activa
    And existe otro usuario "otro@ejemplo.com" con sesión id "sesion-ajena"
    When envío DELETE /auth/sessions/sesion-ajena con la cookie de "sesion@ejemplo.com"
    Then la respuesta tiene status 403 o 404
    And la sesión "sesion-ajena" sigue activa para "otro@ejemplo.com"

  # ============================================================================
  # VALIDACIÓN DE SESIONES
  # ============================================================================

  @sesion @validacion @error-path @security
  Scenario: Petición con sesión expirada (TTL agotado en Redis) devuelve 401
    Given el usuario "sesion@ejemplo.com" tiene una sesión con TTL expirado en Redis
    When envío GET /auth/me con la cookie de esa sesión
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de sesión expirada o no autorizado

  @sesion @validacion @error-path @security
  Scenario: Petición con sessionId de un usuario eliminado de la BD devuelve 401
    Given existe una sesión válida en Redis con sessionId "sesion-usuario-eliminado"
    And el usuario asociado a esa sesión ha sido eliminado de la base de datos
    When envío GET /auth/me con la cookie "sesion-usuario-eliminado"
    Then la respuesta tiene status 401
    And la sesión huérfana puede ser eliminada de Redis

  @sesion @validacion @happy-path
  Scenario: El TTL de la sesión se renueva (sliding window) en cada petición autenticada
    Given el usuario "sesion@ejemplo.com" tiene una sesión activa con TTL de 7 días
    And han transcurrido 3 días desde la creación de la sesión (TTL restante ~4 días)
    When envío GET /auth/me con la cookie de sesión
    Then la respuesta tiene status 200
    And el TTL de la clave Redis "session:<sessionId>" se restablece a aproximadamente 604800 segundos

  @sesion @validacion @error-path @security
  Scenario: Cookie sessionId con valor manipulado devuelve 401
    Given que no hay sesión activa
    When envío GET /auth/me con una cookie "sessionId" con valor "id_inventado_falso_12345"
    Then la respuesta tiene status 401

  # ============================================================================
  # AUTENTICACIÓN JWT BEARER
  # ============================================================================

  @sesion @jwt @happy-path
  Scenario: GET /auth/me con Bearer JWT válido devuelve datos del usuario
    Given el usuario "sesion@ejemplo.com" tiene un access_token JWT válido (HS256, no expirado)
    When envío GET /auth/me con cabecera "Authorization: Bearer <access_token>"
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "id"
    And el cuerpo contiene un campo "email" con valor "sesion@ejemplo.com"

  @sesion @jwt @error-path @security
  Scenario: GET /auth/me con JWT expirado devuelve 401
    Given el usuario "sesion@ejemplo.com" tiene un access_token JWT que ya expiró (exp en el pasado)
    When envío GET /auth/me con cabecera "Authorization: Bearer <access_token_expirado>"
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error relacionado con token expirado o inválido

  @sesion @jwt @error-path @security
  Scenario: GET /auth/me con JWT manipulado (firma inválida) devuelve 401
    Given tengo un access_token JWT con la firma alterada
    When envío GET /auth/me con cabecera "Authorization: Bearer <token_manipulado>"
    Then la respuesta tiene status 401
    And el cuerpo contiene un mensaje de error de token inválido

  @sesion @jwt @error-path @security
  Scenario Outline: GET /auth/me con Authorization header malformado devuelve 401
    Given que el servidor está en línea
    When envío GET /auth/me con cabecera "Authorization: <valor>"
    Then la respuesta tiene status 401

    Examples:
      | valor                     |
      | Bearer                    |
      | Basic dXNlcjpwYXNz        |
      | token_sin_prefijo_bearer  |
      |                           |

  @sesion @jwt @happy-path
  Scenario: POST /auth/refresh con refresh_token válido devuelve nuevo access_token
    Given el usuario "sesion@ejemplo.com" tiene un refresh_token válido
    When envío POST /auth/refresh con:
      | campo         | valor               |
      | refresh_token | <refresh_token>     |
    Then la respuesta tiene status 200
    And el cuerpo contiene un nuevo campo "access_token"
    And el cuerpo puede contener un nuevo "refresh_token" (rotación)

  @sesion @jwt @error-path @security
  Scenario: POST /auth/refresh con refresh_token inválido o revocado devuelve 401
    Given tengo un refresh_token que ya fue usado o revocado
    When envío POST /auth/refresh con ese refresh_token
    Then la respuesta tiene status 401
