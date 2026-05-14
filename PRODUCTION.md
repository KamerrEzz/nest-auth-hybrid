# Guía de Producción — VaultAuth API (NestJS)

Guía para desplegar únicamente el backend REST. Sirve como base para cualquier cliente: frontend propio, app móvil, Postman, o integración directa.

---

## Arquitectura

```
Internet
   │
   ▼
[Nginx / Caddy]  ← TLS termination + reverse proxy
   │
   ▼
NestJS  :3000
   ├── PostgreSQL  :5432  (solo red interna)
   └── Redis       :6379  (solo red interna)
```

---

## Requisitos

| Componente | Versión mínima |
|---|---|
| OS | Ubuntu 22.04 LTS / Debian 12 |
| Node.js | 20 LTS |
| PostgreSQL | 15+ |
| Redis | 7+ |
| RAM | 1 GB (2 GB recomendado) |

---

## Opción A — Docker Compose (recomendado)

El repositorio ya incluye `Dockerfile` y `docker-compose.yml` listos para producción.

### 1. Instalar Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable docker
systemctl start docker
```

### 2. Crear el archivo `.env`

Copia el ejemplo y completa los valores:

```bash
cp .env.example .env
```

Edita `.env` con los valores reales:

```env
# ── Aplicación ──────────────────────────────────────
NODE_ENV=production
PORT=3000
APP_URL=https://api.tudominio.com

# ── Base de datos (Docker interno) ──────────────────
POSTGRES_USER=vaultauth
POSTGRES_PASSWORD=<password-fuerte-aqui>
POSTGRES_DB=vaultauth

# ── Redis (Docker interno) ───────────────────────────
REDIS_PASSWORD=<password-redis-aqui>

# ── JWT ─────────────────────────────────────────────
# Generar con: openssl rand -base64 64
JWT_SECRET=<64-chars-random>
JWT_REFRESH_SECRET=<64-chars-random>
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# ── Sesión ───────────────────────────────────────────
# Generar con: openssl rand -base64 64
SESSION_SECRET=<64-chars-random>
SESSION_MAX_AGE=604800000

# ── TOTP (cifrado AES-256, exactamente 32 chars) ─────
# Generar con: openssl rand -hex 16
TOTP_ENC_KEY=<32-chars-random>

# ── Bcrypt ───────────────────────────────────────────
BCRYPT_ROUNDS=12

# ── CORS ─────────────────────────────────────────────
# Orígenes permitidos, separados por coma
# Si solo usas el API (Postman/móvil), puedes dejarlo vacío
# o poner el dominio de tu frontend:
CORS_ORIGINS=https://auth.tudominio.com

# ── Email (Resend) ───────────────────────────────────
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxx
FROM_EMAIL=no-reply@tudominio.com

# ── OAuth Google (opcional) ──────────────────────────
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=https://api.tudominio.com/auth/google/callback

# ── OAuth Discord (opcional) ─────────────────────────
DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=
DISCORD_CALLBACK_URL=https://api.tudominio.com/auth/discord/callback

# ── Rate limiting ────────────────────────────────────
RATE_LIMIT_TTL=900000
RATE_LIMIT_MAX=100
```

> **Nunca subas `.env` a git.** Ya está en `.gitignore`.

### 3. Generar secretos seguros

```bash
# JWT secrets
openssl rand -base64 64   # copia para JWT_SECRET
openssl rand -base64 64   # copia para JWT_REFRESH_SECRET

# Session secret
openssl rand -base64 64   # copia para SESSION_SECRET

# TOTP key (exactamente 32 chars hex = 16 bytes)
openssl rand -hex 16      # copia para TOTP_ENC_KEY
```

### 4. Levantar el stack

```bash
# Construir y arrancar en background
docker compose up -d --build

# Ver logs en tiempo real
docker compose logs -f app

# Ver estado
docker compose ps
```

El contenedor ejecuta automáticamente `prisma migrate deploy` antes de iniciar.

### 5. Comandos útiles de Docker

```bash
# Reiniciar solo la app (sin reconstruir)
docker compose restart app

# Reconstruir tras cambios de código
docker compose up -d --build app

# Entrar al contenedor
docker compose exec app sh

# Ejecutar comando de Prisma manualmente
docker compose exec app npx prisma migrate status
docker compose exec app npx prisma studio   # UI de la DB (solo desarrollo)

# Detener todo
docker compose down

# Detener y borrar volúmenes (¡borra la DB!)
docker compose down -v
```

---

## Opción B — Manual con PM2

Para quienes prefieren instalar PostgreSQL y Redis en el host directamente.

### 1. Instalar dependencias del sistema

```bash
apt update && apt upgrade -y
apt install -y curl git postgresql postgresql-contrib redis-server build-essential

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
npm install -g pm2
```

### 2. Configurar PostgreSQL

```bash
sudo -u postgres psql <<EOF
CREATE USER vaultauth WITH PASSWORD 'TU_PASSWORD';
CREATE DATABASE vaultauth OWNER vaultauth;
\q
EOF
```

### 3. Configurar Redis

```bash
# Contraseña y solo localhost
sed -i 's/# requirepass foobared/requirepass TU_REDIS_PASSWORD/' /etc/redis/redis.conf
sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
systemctl restart redis-server
```

### 4. Clonar y configurar

```bash
git clone https://github.com/TU_USUARIO/nest-auth-hybrid.git
cd nest-auth-hybrid
cp .env.example .env
# → editar .env con los valores reales (ver sección anterior)

npm install
```

### 5. Migraciones y build

```bash
npx prisma migrate deploy
npx prisma generate
npm run build
```

### 6. Iniciar con PM2

```bash
pm2 start dist/src/main.js --name "vaultauth-api" --env production
pm2 save
pm2 startup   # sigue las instrucciones que imprime para que sobreviva reinicios
```

```bash
# Comandos útiles de PM2
pm2 status
pm2 logs vaultauth-api
pm2 restart vaultauth-api
pm2 monit
```

---

## Reverse proxy

### Nginx

```bash
apt install -y nginx
```

```nginx
# /etc/nginx/sites-available/api.tudominio.com
server {
    listen 80;
    server_name api.tudominio.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.tudominio.com;

    ssl_certificate     /etc/letsencrypt/live/api.tudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.tudominio.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Headers de seguridad
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # No agregar CORS aquí — lo gestiona NestJS

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection 'upgrade';
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Límite de tamaño de request (ajustar si suben archivos)
        client_max_body_size 5m;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/api.tudominio.com /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### Caddy (alternativa con HTTPS automático)

```bash
# Instalar Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install caddy
```

```caddyfile
# /etc/caddy/Caddyfile
api.tudominio.com {
    reverse_proxy localhost:3000

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
```

```bash
systemctl enable caddy && systemctl start caddy
journalctl -u caddy -f   # verificar que obtuvo el certificado
```

---

## SSL con Let's Encrypt (solo Nginx)

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d api.tudominio.com
certbot renew --dry-run   # probar renovación automática
```

---

## DNS

Crea un registro **A** en tu proveedor de DNS:

| Tipo | Nombre | Valor | TTL |
|------|--------|-------|-----|
| A | `api` | `IP_DEL_SERVIDOR` | Auto |

> Si usas Cloudflare, configura el proxy en modo "DNS only" (nube gris) al inicio para verificar que el SSL funciona. Activa CDN (nube naranja) después si lo deseas.

---

## Firewall

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (redirect a HTTPS)
ufw allow 443/tcp   # HTTPS

# NO abrir 3000, 5432, 6379 al exterior
ufw enable
ufw status verbose
```

---

## Seguridad del servidor

### SSH — solo clave pública

```bash
# Asegúrate de haber añadido tu clave pública antes
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
```

### Fail2ban

```bash
apt install -y fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled  = true
maxretry = 5
bantime  = 1h
findtime = 10m

[nginx-http-auth]
enabled = true
EOF

systemctl enable fail2ban && systemctl restart fail2ban
```

### Actualizaciones automáticas de seguridad

```bash
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
```

---

## Integrar con tu propio frontend o cliente

### CORS

En `.env`, pon los orígenes de tus clientes separados por coma:

```env
CORS_ORIGINS=https://mifrontend.com,https://app.mifrontend.com
```

Si el cliente es una app móvil o un cliente sin origen HTTP (Postman, curl, React Native), deja `CORS_ORIGINS` vacío o configura el guard de CORS en `src/config/` para permitir `*` en desarrollo.

### Cookies vs. Bearer Token

El API usa **cookies HttpOnly** para sesión (`sessionId`) más un **CSRF token** en header. Para clientes que no manejan cookies (apps móviles), el flujo típico es:

1. `POST /auth/csrf` → obtener `csrfToken`
2. Incluir el token como header `X-CSRF-Token` en todas las requests mutantes
3. Las cookies se manejan automáticamente si el cliente las soporta

Para clientes mobile sin soporte de cookies, considera exponer también el `accessToken` JWT del response de login (ya viene en el body de `POST /auth/login`).

### Endpoints principales

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/auth/csrf` | Obtener CSRF token |
| POST | `/auth/register` | Registrar usuario |
| POST | `/auth/login` | Login (retorna tokens + cookie) |
| POST | `/auth/refresh` | Renovar access token |
| POST | `/auth/logout` | Cerrar sesión |
| GET | `/auth/me` | Datos del usuario autenticado |
| POST | `/auth/enable-2fa` | Iniciar setup 2FA (retorna QR) |
| POST | `/auth/verify-2fa` | Confirmar código TOTP |
| GET | `/auth/2fa/status` | Estado del 2FA |
| POST | `/auth/disable-2fa` | Desactivar 2FA |
| POST | `/auth/verify-otp` | Verificar OTP de email |

Para la referencia completa de endpoints ver `auth_endpoints.md`.

---

## Backups de la base de datos

### Con Docker Compose

```bash
# Backup
docker compose exec postgres pg_dump -U vaultauth vaultauth | gzip > backup_$(date +%Y%m%d).sql.gz

# Restaurar
gunzip -c backup_20240101.sql.gz | docker compose exec -T postgres psql -U vaultauth vaultauth
```

### Sin Docker (manual)

```bash
cat > /usr/local/bin/backup-db.sh <<'EOF'
#!/bin/bash
DEST=/var/backups/vaultauth
mkdir -p $DEST
sudo -u postgres pg_dump vaultauth | gzip > "$DEST/backup_$(date +%Y%m%d_%H%M%S).sql.gz"
find $DEST -name "*.sql.gz" -mtime +30 -delete
EOF

chmod +x /usr/local/bin/backup-db.sh
echo "0 3 * * * root /usr/local/bin/backup-db.sh" > /etc/cron.d/vaultauth-backup
```

---

## Checklist de producción

- [ ] `.env` configurado con secretos reales y **no en git**
- [ ] `JWT_SECRET` y `JWT_REFRESH_SECRET` aleatorios (≥ 64 chars)
- [ ] `SESSION_SECRET` aleatorio (≥ 64 chars)
- [ ] `TOTP_ENC_KEY` exactamente 32 caracteres hex
- [ ] `BCRYPT_ROUNDS` ≥ 12
- [ ] `NODE_ENV=production`
- [ ] `CORS_ORIGINS` apuntando solo a los clientes autorizados
- [ ] `APP_URL` con la URL pública de la API (`https://api.tudominio.com`)
- [ ] Migraciones ejecutadas (`prisma migrate deploy`)
- [ ] PostgreSQL accesible solo en red interna
- [ ] Redis con contraseña y solo en red interna
- [ ] UFW habilitado con solo 22, 80, 443 abiertos
- [ ] SSH solo con clave pública
- [ ] Fail2ban activo
- [ ] HTTPS válido y renovación automática configurada
- [ ] DNS propagado al servidor correcto
- [ ] PM2 con startup configurado (opción B) o Docker con `restart: unless-stopped`
- [ ] Backups de PostgreSQL programados
