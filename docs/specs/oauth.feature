#language: es
# ==============================================================================
# VaultAuth — Especificaciones BDD: OAuth 2.0
# Dominio: Gestión de apps, Authorization Code + PKCE, token exchange,
#           refresh, userinfo, introspect, revoke
# RFC 6749, RFC 7636 (PKCE), RFC 7662 (Introspection), RFC 7009 (Revocation)
# ==============================================================================

Feature: OAuth 2.0 — Autorización y gestión de aplicaciones
  Como desarrollador o usuario final
  Quiero que el servidor OAuth 2.0 gestione correctamente el ciclo completo
  Desde el registro de aplicaciones hasta el intercambio y renovación de tokens

  Background:
    Given que el servidor VaultAuth está en línea
    And existe un usuario "dev@ejemplo.com" con password "DevPass123!" autenticado

  # ============================================================================
  # GESTIÓN DE APLICACIONES OAUTH (App Management)
  # ============================================================================

  @oauth @apps @happy-path
  Scenario: Crear una aplicación OAuth con datos válidos devuelve clientId y secret en texto plano
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    When envío POST /oauth/apps con:
      | campo        | valor                          |
      | name         | Mi App de Prueba               |
      | redirectUris | ["https://miapp.com/callback"] |
      | scopes       | ["openid", "profile", "email"] |
    Then la respuesta tiene status 201
    And el cuerpo contiene un campo "clientId" (UUID o cadena única)
    And el cuerpo contiene un campo "clientSecret" en texto plano
    And el campo "clientSecret" NO aparecerá en ninguna consulta futura (solo en creación)
    And en la base de datos el "clientSecret" está almacenado como hash bcrypt

  @oauth @apps @error-path @validacion
  Scenario: Crear una aplicación con scope no soportado devuelve 400
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    When envío POST /oauth/apps con:
      | campo        | valor                            |
      | name         | App Mala                         |
      | redirectUris | ["https://miapp.com/callback"]   |
      | scopes       | ["openid", "scope_inexistente"]  |
    Then la respuesta tiene status 400
    And el cuerpo contiene un mensaje indicando el scope inválido

  @oauth @apps @happy-path
  Scenario: GET /oauth/apps devuelve solo las aplicaciones del usuario autenticado
    Given el usuario "dev@ejemplo.com" tiene 2 aplicaciones OAuth registradas
    And el usuario "otro@ejemplo.com" tiene 3 aplicaciones OAuth registradas
    When envío GET /oauth/apps con sesión de "dev@ejemplo.com"
    Then la respuesta tiene status 200
    And el cuerpo es un array con exactamente 2 elementos
    And cada elemento pertenece al usuario "dev@ejemplo.com"

  @oauth @apps @happy-path
  Scenario: Eliminar una aplicación propia elimina el registro
    Given el usuario "dev@ejemplo.com" tiene una aplicación con id "app-propia-123"
    When envío DELETE /oauth/apps/app-propia-123 con sesión de "dev@ejemplo.com"
    Then la respuesta tiene status 200
    And la aplicación "app-propia-123" ya no existe en la base de datos
    And los tokens activos asociados a esa aplicación quedan invalidados

  @oauth @apps @error-path @security
  Scenario: Intentar eliminar la aplicación de otro usuario devuelve 403
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And el usuario "otro@ejemplo.com" tiene una aplicación con id "app-ajena-456"
    When envío DELETE /oauth/apps/app-ajena-456 con sesión de "dev@ejemplo.com"
    Then la respuesta tiene status 403
    And la aplicación "app-ajena-456" sigue existiendo en la base de datos

  @oauth @apps @happy-path @security
  Scenario: Regenerar clientSecret invalida el secret anterior e itera el nuevo
    Given el usuario "dev@ejemplo.com" tiene una aplicación con id "app-regen-789"
    And el secret actual es conocido como "secret-viejo"
    When envío POST /oauth/apps/app-regen-789/regenerate-secret con sesión de "dev@ejemplo.com"
    Then la respuesta tiene status 200
    And el cuerpo contiene un nuevo campo "clientSecret" en texto plano
    And el nuevo secret es diferente a "secret-viejo"
    And autenticar con "secret-viejo" en el flujo OAuth ya NO es posible

  # ============================================================================
  # ENDPOINT DE AUTORIZACIÓN (GET /oauth/authorize)
  # ============================================================================

  @oauth @authorize @error-path @security
  Scenario: Usuario no autenticado es redirigido al login
    Given que no hay sesión activa ni token Bearer
    When envío GET /oauth/authorize con parámetros:
      | param         | valor                                    |
      | client_id     | cliente-valido-abc                       |
      | redirect_uri  | https://miapp.com/callback               |
      | response_type | code                                     |
      | scope         | openid profile                           |
      | state         | estado-aleatorio-csrf                    |
      | code_challenge| E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw |
      | code_challenge_method | S256                             |
    Then la respuesta tiene status 302
    And la cabecera Location contiene "/login" o similar
    And la cabecera Location contiene el parámetro "from" con la URL de retorno codificada

  @oauth @authorize @happy-path
  Scenario: Usuario autenticado con parámetros válidos es redirigido a la pantalla de consentimiento
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And existe una aplicación OAuth con client_id "cliente-valido-abc" y redirect_uri "https://miapp.com/callback"
    When envío GET /oauth/authorize con parámetros válidos (client_id, redirect_uri, response_type=code, scope, state, code_challenge S256)
    Then la respuesta tiene status 302
    And la solicitud de autorización es almacenada en Redis con un "requestId" único
    And la cabecera Location apunta a "/oauth/consent/<requestId>"

  @oauth @authorize @error-path @validacion
  Scenario Outline: Parámetros inválidos en /oauth/authorize devuelven 400
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    When envío GET /oauth/authorize con parámetro "<parametro>" igual a "<valor_invalido>"
    Then la respuesta tiene status 400
    And el cuerpo contiene un mensaje describiendo el error "<descripcion>"

    Examples:
      | parametro     | valor_invalido              | descripcion                          |
      | client_id     | cliente-que-no-existe       | client_id inválido o no encontrado   |
      | redirect_uri  | https://maliciosa.com/hack  | redirect_uri no registrada           |
      | response_type | token                       | response_type no soportado           |
      | response_type | (vacío)                     | response_type requerido              |

  @oauth @authorize @error-path @security
  Scenario: redirect_uri no registrada en la aplicación devuelve 400 (sin redirigir)
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And existe una aplicación con client_id "app-segura" y redirect_uri "https://legitima.com/cb"
    When envío GET /oauth/authorize con redirect_uri "https://atacante.com/robar"
    Then la respuesta tiene status 400
    And la respuesta NO redirige al atacante

  # ============================================================================
  # FLUJO DE CONSENTIMIENTO
  # ============================================================================

  @oauth @consent @happy-path
  Scenario: Usuario aprueba el consentimiento → auth_code emitido, redirect con code y state
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And existe una solicitud de autorización pendiente con requestId "req-abc-123" en Redis
    And la solicitud contiene state "mi-estado-csrf-seguro"
    When envío POST /oauth/authorize con:
      | campo     | valor          |
      | requestId | req-abc-123    |
      | approved  | true           |
    Then la respuesta tiene status 302
    And la cabecera Location es "https://miapp.com/callback?code=<auth_code>&state=mi-estado-csrf-seguro"
    And el auth_code tiene longitud de 128 caracteres hexadecimales (64 bytes)
    And el auth_code está almacenado en la BD con TTL de 10 minutos y flag "used: false"

  @oauth @consent @error-path
  Scenario: Usuario deniega el consentimiento → redirect con error=access_denied
    Given el usuario "dev@ejemplo.com" está autenticado con sesión válida
    And existe una solicitud de autorización pendiente con requestId "req-deny-456" en Redis
    And la solicitud contiene state "mi-estado-csrf-seguro"
    When envío POST /oauth/authorize con:
      | campo     | valor          |
      | requestId | req-deny-456   |
      | approved  | false          |
    Then la respuesta tiene status 302
    And la cabecera Location es "https://miapp.com/callback?error=access_denied&state=mi-estado-csrf-seguro"

  # ============================================================================
  # INTERCAMBIO DE TOKEN (POST /oauth/token — authorization_code grant)
  # ============================================================================

  @oauth @token @happy-path @pkce
  Scenario: Intercambio exitoso con authorization_code y PKCE S256 (cliente público)
    Given existe un auth_code válido "codigo-valido-hex" no usado, no expirado
    And el code_verifier es "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (verifier del challenge S256)
    When envío POST /oauth/token con:
      | campo         | valor                                              |
      | grant_type    | authorization_code                                 |
      | code          | codigo-valido-hex                                  |
      | redirect_uri  | https://miapp.com/callback                         |
      | client_id     | cliente-publico-xyz                                |
      | code_verifier | dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk       |
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "access_token" (JWT HS256)
    And el cuerpo contiene un campo "refresh_token" (96 bytes hex)
    And el cuerpo contiene un campo "token_type" con valor "Bearer"
    And el cuerpo contiene un campo "expires_in" con valor 3600
    And el JWT "access_token" contiene claims: sub, client_id, scope, jti, type:"oauth_access"
    And el auth_code queda marcado como "used: true" en la BD

  @oauth @token @happy-path
  Scenario: Intercambio exitoso con client_secret_post (cliente confidencial)
    Given existe un auth_code válido para el cliente confidencial "cliente-conf-abc"
    When envío POST /oauth/token con:
      | campo         | valor                      |
      | grant_type    | authorization_code         |
      | code          | codigo-conf-valido         |
      | redirect_uri  | https://miapp.com/callback |
      | client_id     | cliente-conf-abc           |
      | client_secret | secreto-en-texto-plano     |
    Then la respuesta tiene status 200
    And el cuerpo contiene "access_token" y "refresh_token"

  @oauth @token @happy-path
  Scenario: Intercambio exitoso con Authorization Basic (client_secret_basic)
    Given existe un auth_code válido para el cliente confidencial "cliente-conf-abc"
    When envío POST /oauth/token con cabecera "Authorization: Basic <base64(clientId:secret)>"
    And body con grant_type=authorization_code, code y redirect_uri
    Then la respuesta tiene status 200
    And el cuerpo contiene "access_token" y "refresh_token"

  @oauth @token @error-path @security
  Scenario: Reutilizar un código ya utilizado devuelve 400
    Given el auth_code "codigo-ya-usado" tiene flag "used: true" en la BD
    When envío POST /oauth/token con ese código
    Then la respuesta tiene status 400
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  @oauth @token @error-path
  Scenario: Código de autorización expirado devuelve 400
    Given el auth_code "codigo-expirado" tiene TTL vencido (más de 10 minutos)
    When envío POST /oauth/token con ese código
    Then la respuesta tiene status 400
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  @oauth @token @error-path @security @pkce
  Scenario: code_verifier incorrecto para el code_challenge devuelve 400
    Given existe un auth_code válido con code_challenge S256 basado en el verifier "verifier-correcto"
    When envío POST /oauth/token con code_verifier "verifier-incorrecto"
    Then la respuesta tiene status 400
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  @oauth @token @error-path @security
  Scenario: redirect_uri que no coincide con la del código devuelve 400
    Given existe un auth_code válido emitido para redirect_uri "https://legitima.com/cb"
    When envío POST /oauth/token con redirect_uri "https://diferente.com/cb"
    Then la respuesta tiene status 400
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  @oauth @token @error-path @security
  Scenario: client_secret incorrecto para cliente confidencial devuelve 401
    Given existe un auth_code válido para cliente confidencial "cliente-conf-abc"
    When envío POST /oauth/token con client_secret "secreto-equivocado"
    Then la respuesta tiene status 401
    And el cuerpo contiene un campo "error" con valor "invalid_client"

  # ============================================================================
  # REFRESH TOKEN
  # ============================================================================

  @oauth @refresh @happy-path
  Scenario: Refresh token válido devuelve nuevo access_token y nuevo refresh_token, y revoca el anterior
    Given el usuario tiene un refresh_token válido "refresh-tok-abc-hex-192-chars"
    When envío POST /oauth/token con:
      | campo         | valor                        |
      | grant_type    | refresh_token                |
      | refresh_token | refresh-tok-abc-hex-192-chars |
      | client_id     | cliente-valido-abc           |
    Then la respuesta tiene status 200
    And el cuerpo contiene un nuevo "access_token"
    And el cuerpo contiene un nuevo "refresh_token" diferente al anterior
    And el refresh_token anterior "refresh-tok-abc-hex-192-chars" ya no es válido (revocado)

  @oauth @refresh @error-path @security
  Scenario: Usar un refresh_token revocado devuelve 401
    Given el refresh_token "refresh-revocado-xyz" ha sido revocado o marcado como inválido
    When envío POST /oauth/token con ese refresh_token
    Then la respuesta tiene status 401
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  @oauth @refresh @error-path @security
  Scenario: Usar el refresh_token antiguo después de la rotación devuelve 401 (replay protection)
    Given el usuario usó el refresh_token "refresh-antiguo-abc" y recibió "refresh-nuevo-xyz"
    When envío POST /oauth/token con el refresh_token "refresh-antiguo-abc"
    Then la respuesta tiene status 401
    And el cuerpo contiene un campo "error" con valor "invalid_grant"

  # ============================================================================
  # USERINFO (GET /oauth/userinfo)
  # ============================================================================

  @oauth @userinfo @happy-path
  Scenario: Acceso a /oauth/userinfo con scope openid devuelve sub
    Given el usuario tiene un access_token válido con scope "openid"
    When envío GET /oauth/userinfo con cabecera "Authorization: Bearer <access_token>"
    Then la respuesta tiene status 200
    And el cuerpo contiene un campo "sub" con el identificador del usuario
    And el cuerpo NO contiene "name" ni "email" (no fueron solicitados en el scope)

  @oauth @userinfo @happy-path
  Scenario: Acceso a /oauth/userinfo con scope openid profile email devuelve claims completos
    Given el usuario tiene un access_token válido con scope "openid profile email"
    When envío GET /oauth/userinfo con cabecera "Authorization: Bearer <access_token>"
    Then la respuesta tiene status 200
    And el cuerpo contiene los campos "sub", "name", "email", "email_verified"
    And el campo "email" tiene el valor del email del usuario

  @oauth @userinfo @error-path @security
  Scenario Outline: Acceso a /oauth/userinfo con token inválido devuelve 401
    Given el servidor está en línea
    When envío GET /oauth/userinfo con cabecera "Authorization: Bearer <token>"
    Then la respuesta tiene status 401

    Examples:
      | token                  |
      | token_expirado_jwt     |
      | token_revocado_xxx     |
      | token_completamente_falso |

  # ============================================================================
  # INTROSPECCIÓN (POST /oauth/introspect)
  # ============================================================================

  @oauth @introspect @happy-path
  Scenario: Introspección de token activo devuelve metadatos completos
    Given existe un access_token activo "token-activo-abc" para el usuario "dev@ejemplo.com"
    When envío POST /oauth/introspect con:
      | campo | valor           |
      | token | token-activo-abc |
    Then la respuesta tiene status 200
    And el cuerpo contiene "active: true"
    And el cuerpo contiene los campos "scope", "client_id", "sub", "exp", "username"

  @oauth @introspect @error-path
  Scenario Outline: Introspección de token inactivo devuelve active:false
    Given el servidor está en línea
    When envío POST /oauth/introspect con token "<token>"
    Then la respuesta tiene status 200
    And el cuerpo contiene "active: false"
    And el cuerpo NO contiene otros campos de metadatos

    Examples:
      | token                |
      | token-expirado-abc   |
      | token-revocado-xyz   |
      | token-inexistente    |

  # ============================================================================
  # REVOCACIÓN (POST /oauth/revoke)
  # ============================================================================

  @oauth @revoke @happy-path
  Scenario: Revocar un access_token siempre devuelve 200 (idempotente)
    Given existe un access_token activo "access-tok-rev-abc"
    When envío POST /oauth/revoke con:
      | campo | valor             |
      | token | access-tok-rev-abc |
    Then la respuesta tiene status 200
    And el token "access-tok-rev-abc" queda marcado como revocado
    When envío POST /oauth/revoke con el mismo token nuevamente
    Then la respuesta tiene status 200 (idempotente)

  @oauth @revoke @happy-path @security
  Scenario: Revocar un refresh_token hace que su uso posterior falle
    Given el usuario tiene un refresh_token activo "refresh-tok-rev-xyz"
    When envío POST /oauth/revoke con:
      | campo | valor              |
      | token | refresh-tok-rev-xyz |
    Then la respuesta tiene status 200
    When intento usar "refresh-tok-rev-xyz" en POST /oauth/token con grant_type=refresh_token
    Then la respuesta tiene status 401
    And el cuerpo contiene "error: invalid_grant"

  @oauth @revoke @happy-path
  Scenario: Revocar un token inexistente también devuelve 200 (idempotente)
    Given el servidor está en línea
    When envío POST /oauth/revoke con token "token-que-nunca-existio"
    Then la respuesta tiene status 200
