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

## Circuito

1. El camionero escanea el QR del cartel (`/cartel.html`) y completa `/registro.html`: empresa, dominio, nombre, titular o chofer, teléfono y mail. Si no puede, usa el formulario en papel (segunda hoja del cartel).
2. El generador ve los formularios recibidos, revisa los datos contra el carnet, carga el comprobante y emite UN código para ese camión. La empresa es texto libre.
3. El verificador controla el código, retiene el carnet y entrega una llave de baño (el sistema no deja dar una llave que otro camión todavía tiene).
4. Para salir, el camionero escribe al WhatsApp del cartel (se configura en Administración → Configuración). El supervisor revisa el baño con la tabla de cobros (Administración → Tabla de cobros): si algo está mal se cobra el equivalente en litros y recién entonces se devuelve el carnet.

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
