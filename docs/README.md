# VaultAuth — Documentación

VaultAuth es un servidor de autorización OAuth 2.0 construido con NestJS que implementa autenticación por email/contraseña, autenticación de dos factores (TOTP), sesiones basadas en Redis, JSON Web Tokens (JWT) y el flujo OAuth 2.0 Authorization Code con PKCE. Forma parte de un sistema de tres repositorios: el servidor de autorización (`nest-auth-hybrid`, puerto 3000), el frontend de login y portal de desarrollador (`next-auth-hybrid`, puerto 3001), y una aplicación de demostración OAuth (`vaultauth-demo-app`, puerto 3002).

---

## Índice de documentación

### Referencia de API

| Documento                    | Descripción                                                                      |
| ---------------------------- | -------------------------------------------------------------------------------- |
| [api/auth.md](api/auth.md)   | Endpoints de autenticación: registro, login, sesiones, 2FA, cambio de contraseña |
| [api/oauth.md](api/oauth.md) | Endpoints OAuth 2.0: apps, authorize, token, userinfo, introspect, revoke        |

### Arquitectura

| Documento                                              | Descripción                                                                      |
| ------------------------------------------------------ | -------------------------------------------------------------------------------- |
| [architecture/system.md](architecture/system.md)       | Visión del sistema: componentes, modelo de datos, flujos de red, infraestructura |
| [architecture/technical.md](architecture/technical.md) | Decisiones de diseño internas, estrategia de tokens, concurrencia, seguridad     |

### Guías

| Documento                                    | Descripción                                                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------ |
| [guides/production.md](guides/production.md) | Guía de despliegue en producción: variables de entorno, Docker, Redis, base de datos |

### Especificaciones BDD (Gherkin)

| Archivo                                              | Dominio                                                                                 |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [specs/auth.feature](specs/auth.feature)             | Registro, login, bloqueo de cuenta y cambio de contraseña                               |
| [specs/two-factor.feature](specs/two-factor.feature) | Configuración 2FA (TOTP), flujo de login con OTP, estado y desactivación                |
| [specs/session.feature](specs/session.feature)       | Ciclo de vida de sesiones, gestión multi-sesión, validación, JWT Bearer                 |
| [specs/oauth.feature](specs/oauth.feature)           | Gestión de apps OAuth, Authorization Code + PKCE, refresh, userinfo, introspect, revoke |
| [specs/rate-limit.feature](specs/rate-limit.feature) | Rate limiting en OAuth, bloqueo por fallos de login, protección CSRF                    |

---

## Especificaciones BDD — ¿Qué son y cómo usarlas?

Los archivos `.feature` en `docs/specs/` son especificaciones ejecutables escritas en **Gherkin**, el lenguaje de comportamiento legible por humanos que usan herramientas como **Cucumber** (JavaScript/Java), **behave** (Python) o **SpecFlow** (.NET).

Cada archivo describe el comportamiento esperado del sistema mediante escenarios estructurados con la sintaxis **Given / When / Then**:

- **Given** — el estado inicial del sistema antes de la acción.
- **When** — la acción que realiza el usuario o sistema.
- **Then** — el resultado esperado observable.
- **And / But** — continúan el paso anterior del mismo tipo.

### Ejecutar las specs con Cucumber.js

```bash
# Instalar dependencias
npm install --save-dev @cucumber/cucumber

# Crear step definitions en test/steps/
# Ejecutar
npx cucumber-js docs/specs/**/*.feature
```

### Ejecutar las specs con behave (Python)

```bash
pip install behave
behave docs/specs/
```

### Uso como documentación viva

Aunque los step definitions no estén implementados, los archivos `.feature` sirven como **documentación viva** del comportamiento del sistema: describen exactamente qué debe ocurrir ante cada caso de uso, incluyendo casos felices, errores, validaciones y comportamientos de seguridad. Son la fuente de verdad para QA, revisiones de código y onboarding de nuevos desarrolladores.

---

> Para el historial de cambios del sistema, consulta [CHANGELOG.md](../CHANGELOG.md).
