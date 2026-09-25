// Acceso a la base. En Vercel usa Neon (DATABASE_URL); en la PC, si no hay
// DATABASE_URL, usa PGlite guardado en la carpeta .data/ (se crea sola).
import bcrypt from 'bcryptjs';

let runner = null;

async function getRunner() {
  if (runner) return runner;
  const url = process.env.DATABASE_URL;
  if (url) {
    const { neon } = await import('@neondatabase/serverless');
    const sql = neon(url);
    runner = (text, params = []) => sql.query(text, params);
  } else {
    if (process.env.VERCEL) throw new Error('Falta DATABASE_URL: conectá la base Neon al proyecto en Vercel.');
    const { PGlite } = await import('@electric-sql/pglite');
    const { mkdirSync } = await import('node:fs');
    mkdirSync('./.data', { recursive: true });
    const db = new PGlite('./.data/pglite');
    await db.waitReady;
    runner = async (text, params = []) => (await db.query(text, params)).rows;
  }
  return runner;
}

let ready = null;
export function query(text, params) {
  ready ??= init().catch((e) => { ready = null; throw e; });
  return ready.then(() => runner(text, params));
}

export async function one(text, params) {
  const rows = await query(text, params);
  return rows[0] ?? null;
}

const DEFAULT_CONFIG = {
  codigoValidezDias: 30,
  estadiaHorasMax: 24,
  maxCodigosPorGeneracion: 20,
  headerTexto: 'ESTACIÓN FERREYRA S.R.L.',
  notifEmailTo: 'estacionferreyrasrl@gmail.com',
  notifEmailCc: 'candeechavarria@gmail.com',
  alertaEstadiaHoras: 22,
  whatsappSalida: '',
  alertaDatosHoras: 4,
};

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('admin','generador','verificador')),
    hash TEXT NOT NULL,
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    debe_cambiar BOOLEAN NOT NULL DEFAULT FALSE,
    intentos_fallidos INT NOT NULL DEFAULT 0,
    bloqueado_hasta TIMESTAMPTZ,
    creado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
    creado_por TEXT,
    UNIQUE (rol, username)
  )`,
  // Rol combinado "mixto" (generador y verificador a la vez).
  `ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check`,
  `ALTER TABLE usuarios ADD CONSTRAINT usuarios_rol_check CHECK (rol IN ('admin','generador','verificador','mixto'))`,
  `CREATE TABLE IF NOT EXISTS empresas (
    id SERIAL PRIMARY KEY,
    nombre TEXT NOT NULL,
    cuit TEXT NOT NULL DEFAULT '',
    activa BOOLEAN NOT NULL DEFAULT TRUE,
    creado_en TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS codigos (
    id SERIAL PRIMARY KEY,
    codigo TEXT NOT NULL UNIQUE,
    empresa_id INT REFERENCES empresas(id),
    empresa TEXT NOT NULL,
    comprobante TEXT NOT NULL,
    creado_por TEXT NOT NULL,
    generado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
    vence_en TIMESTAMPTZ NOT NULL,
    estadia_horas INT NOT NULL,
    estado TEXT NOT NULL DEFAULT 'Creado' CHECK (estado IN ('Creado','En Sitio','Finalizado')),
    patente TEXT,
    ingreso_en TIMESTAMPTZ,
    verifico TEXT,
    egreso_en TIMESTAMPTZ,
    egreso_por TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS codigos_estado_idx ON codigos (estado)`,
  `CREATE INDEX IF NOT EXISTS codigos_generado_idx ON codigos (generado_en DESC)`,
  `CREATE TABLE IF NOT EXISTS auditoria (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    usuario TEXT NOT NULL,
    rol TEXT NOT NULL,
    accion TEXT NOT NULL,
    detalle TEXT NOT NULL DEFAULT ''
  )`,
  // Columnas de la API para empresas, que se quitó.
  `ALTER TABLE empresas DROP COLUMN IF EXISTS api_habilitada, DROP COLUMN IF EXISTS api_token_hash, DROP COLUMN IF EXISTS api_token_fin`,
  `CREATE INDEX IF NOT EXISTS auditoria_ts_idx ON auditoria (ts DESC)`,
  // Circuito con datos del chofer, carnet retenido, llave de baño y control de salida.
  `ALTER TABLE codigos ADD COLUMN IF NOT EXISTS conductor TEXT,
     ADD COLUMN IF NOT EXISTS conductor_rol TEXT,
     ADD COLUMN IF NOT EXISTS telefono TEXT,
     ADD COLUMN IF NOT EXISTS email TEXT,
     ADD COLUMN IF NOT EXISTS carnet_retenido BOOLEAN NOT NULL DEFAULT FALSE,
     ADD COLUMN IF NOT EXISTS llave_bano TEXT,
     ADD COLUMN IF NOT EXISTS control_ok BOOLEAN,
     ADD COLUMN IF NOT EXISTS control_items JSONB,
     ADD COLUMN IF NOT EXISTS control_obs TEXT,
     ADD COLUMN IF NOT EXISTS litros_cobrados NUMERIC(10,2),
     ADD COLUMN IF NOT EXISTS bano_optimo BOOLEAN`,
  `CREATE TABLE IF NOT EXISTS solicitudes (
    id SERIAL PRIMARY KEY,
    creado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
    origen TEXT NOT NULL CHECK (origen IN ('qr','papel')),
    empresa TEXT NOT NULL,
    patente TEXT NOT NULL,
    conductor TEXT NOT NULL,
    conductor_rol TEXT NOT NULL CHECK (conductor_rol IN ('titular','chofer')),
    telefono TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    estado TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','emitida','descartada')),
    codigo TEXT,
    ip_hash TEXT
  )`,
  // Aceptación de las bases y condiciones (casilla del QR o firma del formulario en papel).
  `ALTER TABLE solicitudes ADD COLUMN IF NOT EXISTS acepto_bases_en TIMESTAMPTZ,
     ADD COLUMN IF NOT EXISTS bases_version TEXT`,
  `ALTER TABLE codigos ADD COLUMN IF NOT EXISTS bases_aceptadas_en TIMESTAMPTZ,
     ADD COLUMN IF NOT EXISTS bases_version TEXT,
     ADD COLUMN IF NOT EXISTS bases_via TEXT,
     ADD COLUMN IF NOT EXISTS aviso_datos_en TIMESTAMPTZ`,
  `CREATE INDEX IF NOT EXISTS solicitudes_estado_idx ON solicitudes (estado, creado_en DESC)`,
  // Qué revisa el supervisor en el baño y cuántos litros se cobran si está mal.
  `CREATE TABLE IF NOT EXISTS control_items (
    id SERIAL PRIMARY KEY,
    descripcion TEXT NOT NULL,
    litros NUMERIC(10,2) NOT NULL CHECK (litros >= 0),
    orden INT NOT NULL DEFAULT 0,
    activo BOOLEAN NOT NULL DEFAULT TRUE
  )`,
  `CREATE TABLE IF NOT EXISTS config (
    id INT PRIMARY KEY CHECK (id = 1),
    datos JSONB NOT NULL
  )`,
];

async function init() {
  const run = await getRunner();
  for (const stmt of SCHEMA) await run(stmt);
  await run(`INSERT INTO config (id, datos) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`, [JSON.stringify(DEFAULT_CONFIG)]);

  // Primer administrador: se crea una sola vez, con la clave de INITIAL_ADMIN_PASSWORD,
  // y el sistema le pide cambiarla en el primer ingreso.
  const admins = await run(`SELECT 1 FROM usuarios WHERE rol = 'admin' LIMIT 1`);
  const inicial = process.env.INITIAL_ADMIN_PASSWORD;
  if (admins.length === 0 && inicial) {
    await run(
      `INSERT INTO usuarios (username, rol, hash, debe_cambiar, creado_por) VALUES ('estacion', 'admin', $1, TRUE, 'sistema')
       ON CONFLICT DO NOTHING`,
      [await bcrypt.hash(inicial, 10)],
    );
  }
}

export async function getConfig() {
  const row = await one(`SELECT datos FROM config WHERE id = 1`);
  const datos = typeof row.datos === 'string' ? JSON.parse(row.datos) : row.datos;
  return { ...DEFAULT_CONFIG, ...datos };
}

export async function audit(usuario, rol, accion, detalle = '') {
  await query(`INSERT INTO auditoria (usuario, rol, accion, detalle) VALUES ($1, $2, $3, $4)`, [usuario, rol, accion, detalle]);
}
