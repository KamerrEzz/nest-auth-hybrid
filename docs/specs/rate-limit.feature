#language: es
# ==============================================================================
# VaultAuth — Especificaciones BDD: Rate Limiting y Protecciones de Seguridad
# Dominio: Límites de tasa en OAuth, bloqueo por fallos de login, CSRF
# Implementación: Redis INCR con ventana de 60s, lockout con clave Redis TTL 15min
# ==============================================================================

Feature: Rate limiting, bloqueo de cuenta y protección CSRF
  Como sistema de seguridad de VaultAuth
  Quiero limitar las peticiones abusivas y proteger los endpoints críticos
  Para prevenir ataques de fuerza bruta, DDoS y CSRF

  Background:
    Given que el servidor VaultAuth está en línea
    And el backend Redis está disponible y operativo

  # ============================================================================
  # RATE LIMITING EN ENDPOINTS OAUTH
  # ============================================================================

  @rate-limit @oauth @security
  Scenario: 21 peticiones a GET /oauth/authorize desde la misma IP en 60s → 429 en la 21a
    Given una IP "192.168.1.100" sin peticiones previas en la ventana actual
    And existe un usuario autenticado con sesión válida
    And existe una aplicación OAuth con client_id "app-rate-test" y redirect_uri válida
    When realizo 20 peticiones GET a /oauth/authorize con parámetros válidos desde la IP "192.168.1.100"
    Then las 20 peticiones devuelven status 200 o 302 (respuestas normales)
    When realizo la petición número 21 desde la misma IP "192.168.1.100"
    Then la respuesta tiene status 429
    And el cuerpo contiene un campo "message" indicando que se superó el límite de peticiones
    And la cabecera de respuesta contiene "Retry-After" con el tiempo de espera en segundos

  @rate-limit @oauth @security
  Scenario: El contador de rate limit se resetea después de la ventana de 60 segundos
    Given la IP "192.168.1.100" ya usó las 20 peticiones permitidas en la ventana actual
    And la clave Redis de rate limit para "192.168.1.100" tiene un TTL que expirará en breve
    When transcurren 60 segundos (la ventana de rate limit expira)
    And realizo una nueva petición GET a /oauth/authorize desde "192.168.1.100"
    Then la respuesta NO tiene status 429
    And la respuesta tiene status 200 o 302 (petición procesada normalmente)
    And el contador Redis para "192.168.1.100" vuelve a ser 1

  @rate-limit @oauth @security
  Scenario: El rate limit es por IP — IPs diferentes tienen contadores independientes
    Given la IP "10.0.0.1" realizó 20 peticiones a /oauth/authorize (límite alcanzado)
    When realizo una petición GET a /oauth/authorize desde la IP "10.0.0.2"
    Then la respuesta desde "10.0.0.2" NO tiene status 429
    And la respuesta desde "10.0.0.2" tiene status 200 o 302

  @rate-limit @oauth @security
  Scenario: 21 peticiones a POST /oauth/token desde la misma IP en 60s → 429 en la 21a
    Given una IP "192.168.1.200" sin peticiones previas en la ventana actual
    And existe un auth_code válido para el intercambio de token
    When realizo 20 peticiones POST a /oauth/token (cada una con un código diferente) desde "192.168.1.200"
    Then las 20 peticiones son procesadas (status 200 o 400 según validez del código)
    When realizo la petición número 21 a POST /oauth/token desde "192.168.1.200"
    Then la respuesta tiene status 429
    And el cuerpo contiene un mensaje de rate limit superado

  @rate-limit @oauth @security
  Scenario Outline: Rate limit se aplica independientemente al endpoint correcto
    Given la IP "<ip>" no ha alcanzado el límite en el endpoint "<endpoint>"
    When realizo 21 peticiones a "<endpoint>" desde "<ip>"
    Then la petición número 21 devuelve status 429

    Examples:
      | ip            | endpoint            |
      | 172.16.0.1    | GET /oauth/authorize |
      | 172.16.0.2    | POST /oauth/token    |

  # ============================================================================
  # BLOQUEO DE CUENTA POR INTENTOS FALLIDOS (Login Lockout)
  # ============================================================================

  @rate-limit @lockout @security
  Scenario: 5 intentos de login fallidos consecutivos bloquean la cuenta
    Given existe un usuario con email "objetivo@ejemplo.com" y password "CorrectaPass1!"
    And no existe la clave Redis "lockout:objetivo@ejemplo.com"
    And no existe la clave Redis de intentos fallidos para "objetivo@ejemplo.com"
    When realizo 5 peticiones POST a /auth/login con password incorrecta para "objetivo@ejemplo.com"
    Then el 5to intento devuelve status 401
    And la clave Redis "lockout:objetivo@ejemplo.com" existe con TTL aproximado de 900 segundos
    And la clave Redis de intentos fallidos para "objetivo@ejemplo.com" refleja 5 intentos

  @rate-limit @lockout @security
  Scenario: Petición de login durante el período de bloqueo devuelve 429 con mensaje "locked"
    Given existe un usuario con email "bloqueado@ejemplo.com"
    And la clave Redis "lockout:bloqueado@ejemplo.com" existe con TTL 750 (12.5 minutos restantes)
    When envío POST /auth/login con:
      | campo    | valor                  |
      | email    | bloqueado@ejemplo.com  |
      | password | CualquierPassword1!    |
    Then la respuesta tiene status 429
    And el cuerpo contiene un campo "message" que incluye "locked" o similar
    And el cuerpo puede contener un campo indicando los segundos restantes del bloqueo

  @rate-limit @lockout @security
  Scenario: Después de 15 minutos el bloqueo expira y se puede volver a intentar
    Given existe un usuario con email "expirado@ejemplo.com" y password "CorrectaPass1!"
    And la clave Redis "lockout:expirado@ejemplo.com" expiró hace 1 segundo
    When envío POST /auth/login con:
      | campo    | valor                 |
      | email    | expirado@ejemplo.com  |
      | password | CorrectaPass1!        |
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "access_token"
    And la clave Redis "lockout:expirado@ejemplo.com" ya no existe

  @rate-limit @lockout @security @happy-path
  Scenario: Un login exitoso antes de 5 fallos resetea el contador de intentos
    Given existe un usuario con email "seguro@ejemplo.com" y password "CorrectaPass1!"
    And existen 3 intentos fallidos registrados para "seguro@ejemplo.com" (sin bloqueo)
    When envío POST /auth/login con:
      | campo    | valor               |
      | email    | seguro@ejemplo.com  |
      | password | CorrectaPass1!      |
    Then la respuesta tiene status 200
    And la clave Redis de intentos fallidos para "seguro@ejemplo.com" ya no existe o es 0
    And la clave Redis "lockout:seguro@ejemplo.com" no existe

  @rate-limit @lockout @security
  Scenario: El contador de intentos fallidos es por email, no por IP
    Given existe un usuario con email "porEmail@ejemplo.com" y password "CorrectaPass1!"
    When realizo 3 intentos fallidos desde la IP "1.2.3.4" para "porEmail@ejemplo.com"
    And realizo 2 intentos fallidos desde la IP "5.6.7.8" para "porEmail@ejemplo.com"
    Then la cuenta "porEmail@ejemplo.com" queda bloqueada (5 intentos fallidos en total)
    And la clave Redis "lockout:porEmail@ejemplo.com" existe

  # ============================================================================
  # PROTECCIÓN CSRF
  # ============================================================================

  @csrf @security @error-path
  Scenario: POST /oauth/apps sin token CSRF devuelve 403
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And NO incluyo ningún token CSRF en la petición
    When envío POST /oauth/apps con body válido:
      | campo        | valor                          |
      | name         | Mi App                         |
      | redirectUris | ["https://miapp.com/callback"] |
      | scopes       | ["openid"]                     |
    Then la respuesta tiene status 403
    And el cuerpo contiene un mensaje indicando falta de token CSRF o token inválido

  @csrf @security @happy-path
  Scenario: POST /oauth/apps con token CSRF válido devuelve 201
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And obtengo un token CSRF válido mediante GET /auth/csrf
    When envío POST /oauth/apps con:
      | campo        | valor                          |
      | name         | Mi App Con CSRF                |
      | redirectUris | ["https://miapp.com/callback"] |
      | scopes       | ["openid"]                     |
    And incluyo el token CSRF en la cabecera "x-csrf-token" o como campo del body
    Then la respuesta tiene status 201
    And el cuerpo contiene "clientId" y "clientSecret"

  @csrf @security @error-path
  Scenario: POST /oauth/apps con token CSRF manipulado devuelve 403
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    When envío POST /oauth/apps con token CSRF "token-csrf-falso-manipulado" en la cabecera
    Then la respuesta tiene status 403

  @csrf @security @error-path
  Scenario Outline: Endpoints mutantes del portal de desarrollador requieren CSRF válido
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And NO incluyo ningún token CSRF
    When envío <metodo> <endpoint> sin token CSRF
    Then la respuesta tiene status 403

    Examples:
      | metodo | endpoint                              |
      | POST   | /oauth/apps                           |
      | DELETE | /oauth/apps/alguna-app-id             |
      | POST   | /oauth/apps/alguna-app-id/regenerate-secret |

  @csrf @security @happy-path
  Scenario: GET /auth/csrf devuelve un token CSRF válido para el usuario autenticado
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    When envío GET /auth/csrf
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "csrfToken" de tipo string no vacío
    And el token es único por sesión (diferentes llamadas pueden devolver tokens diferentes)
