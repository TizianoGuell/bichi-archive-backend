# Threads Gallery Backend

API de Threads Gallery Spot con Express + SQLite.

## Requisitos

- Node.js 22+

## Configuracion

1. Instalar dependencias:

```bash
npm install
```

2. Crear `.env` a partir de `.env.example`:

```env
API_PORT=4000
CORS_ORIGIN="http://localhost:8080"
SQLITE_PATH="data/app.sqlite"
JWT_SECRET="change-this-secret"
```

## Desarrollo

```bash
npm run dev
```

API: `http://localhost:4000`

## Crear admin

PowerShell:

```powershell
$env:ADMIN_EMAIL="admin@bichi.com"; $env:ADMIN_PASSWORD="admin123"; npm run create:admin
```
