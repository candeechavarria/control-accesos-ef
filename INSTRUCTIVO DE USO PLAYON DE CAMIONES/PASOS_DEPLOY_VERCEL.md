# Publicar el prototipo en Vercel — paso a paso

Vas a necesitar **dos archivos** de tu carpeta:
- `index.html`
- `logo_ef.png`

(El archivo `prototipo_control_accesos.html` es el original; podés ignorarlo para el deploy, son idénticos.)

Tiempo total estimado: **10 minutos**.

---

## Parte 1 · GitHub (4 minutos)

### 1.1 Crear cuenta o iniciar sesión
- Abrí en tu navegador: https://github.com
- Si no tenés cuenta: clic en **"Sign up"** arriba a la derecha. Usá tu mail `candeechavarria@gmail.com`. Confirmás el mail (te llega un código).
- Si ya tenés cuenta: clic en **"Sign in"** y entrás.

### 1.2 Crear un repositorio nuevo
- Logueada, clic en el ícono **`+`** arriba a la derecha (al lado de tu avatar) → **"New repository"**.
- Completá:
  - **Repository name**: `control-accesos-ef`
  - **Description** (opcional): `Sistema de Control de Accesos · Estación Ferreyra SRL`
  - Dejá marcado **Public** (necesario para que Vercel te lo deploye gratis).
  - **NO marqués nada** de "Add a README", ".gitignore" ni "license".
- Clic en **"Create repository"** abajo.

### 1.3 Subir los 2 archivos
- En la página del repo recién creado vas a ver un cartel grande. Buscá el texto **"uploading an existing file"** (es un link, va con letra azul más chica, en el medio de la página).
- Clic ahí.
- Te aparece una zona gris grande que dice "Drag files here". Arrastrá desde el explorador de Windows **los dos archivos** desde tu carpeta:
  - `index.html`
  - `logo_ef.png`
- Carpeta de origen: `C:\Users\cande\OneDrive\Documentos\Claude\Projects\INSTRUCTIVO DE USO PLAYON DE CAMIONES`
- Abajo de la zona de archivos, en "Commit changes":
  - Mensaje (cualquiera): `Primera versión`
- Clic en el botón verde **"Commit changes"** abajo.

✅ Listo Parte 1. Tu código está en GitHub.

---

## Parte 2 · Vercel (4 minutos)

### 2.1 Crear cuenta vinculada a GitHub
- Abrí: https://vercel.com
- Clic en **"Sign Up"** arriba a la derecha.
- En las opciones de registro, elegí **"Continue with GitHub"** (con el logo del gatito).
- Te va a pedir autorizar Vercel a leer tus repos. Aceptá.
- Si te hace algunas preguntas (nombre de equipo, plan), elegí **"Hobby"** (gratuito).

### 2.2 Importar el proyecto
- Una vez dentro del dashboard, clic en **"Add New..."** arriba a la derecha → **"Project"**.
- Te va a mostrar la lista de tus repos de GitHub.
- Buscá `control-accesos-ef` y clic en el botón **"Import"** que tiene al lado.
- En la pantalla de configuración **NO TOQUES NADA**, todo viene bien por defecto.
- Clic en el botón **"Deploy"** abajo.

### 2.3 Esperar el build
- Vercel te muestra una pantalla con un confeti animado y el log de deploy.
- Tarda **30 a 60 segundos**.
- Cuando termina, vas a ver el preview del sitio y un botón **"Continue to Dashboard"** o **"Visit"**.

✅ Listo Parte 2.

---

## URL final

Vercel te asigna automáticamente una URL como:

```
https://control-accesos-ef.vercel.app
```

Esa URL es **pública y gratis para siempre**. Compartila con quien quieras.

---

## Si más adelante hacés cambios

Cualquier cambio que hagas localmente al archivo HTML lo subís de nuevo a GitHub (mismo flujo: en el repo, "Add file" → "Upload files" → arrastrar). Vercel **detecta el cambio automáticamente** y re-despliega solo. Sin tocar nada.

---

## Si te trabás

Avisame en qué paso estás y te ayudo. Las trabas más comunes:
- **GitHub te pide configurar 2FA**: lo hacés y seguís, te lleva 1 minuto.
- **Vercel no ve tu repo**: en la pantalla de Import, hay un link "Adjust GitHub App Permissions" para darle acceso al repo.
- **El sitio carga pero el logo no aparece**: revisá que subiste `logo_ef.png` con ese nombre exacto (todo minúsculas).
