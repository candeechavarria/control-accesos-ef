# Control de Accesos · Estación Ferreyra

Códigos de ingreso para el playón de camiones. Publicado en https://control-accesos-ef.vercel.app

- `public/index.html`: toda la interfaz (generador, verificador, administración).
- `api/index.js`: el servidor. Todas las rutas `/api/*` pasan por acá.
- `lib/db.js`: base de datos. Crea las tablas sola la primera vez.
- `lib/auth.js`: sesiones y claves.

## Variables de entorno (Vercel → Settings → Environment Variables)

| Variable | Para qué |
|---|---|
| `DATABASE_URL` | Base Neon. La carga sola la integración de Neon al conectarla al proyecto. |
| `SESSION_SECRET` | Firma las sesiones. Si se cambia, se cierran todas las sesiones abiertas. |
| `INITIAL_ADMIN_PASSWORD` | Clave temporal del usuario `estacion` (admin). Solo se usa la primera vez; el sistema pide cambiarla al entrar. |

## Reglas

- Las claves y PIN se guardan cifrados (bcrypt). Nadie los puede ver.
- 5 intentos fallidos seguidos bloquean al usuario 15 minutos.
- Deshabilitar un usuario le corta la sesión al instante.
- Un código vale para un solo ingreso y un solo egreso, y vence a los N días de generado (configurable).
- Los mails de aviso todavía no están conectados: los eventos quedan en Auditoría.

## Probar en la PC

```
npm install
set INITIAL_ADMIN_PASSWORD=una-clave-de-prueba
npm run dev
```

Abre en http://localhost:3000 con una base local en `.data/` (sin DATABASE_URL).
