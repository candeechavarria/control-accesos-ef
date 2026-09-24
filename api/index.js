// Única función del servidor: todas las rutas /api/* llegan acá (ver vercel.json).
import crypto from 'node:crypto';
import { query, one, getConfig, audit } from '../lib/db.js';
import { checkCredentials, getSession, setSessionCookie, clearSessionCookie, hashClave } from '../lib/auth.js';

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}
const fail = (status, msg) => { throw new HttpError(status, msg); };

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  if (req.body !== undefined) return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body ?? {});
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (raw.length > 100_000) fail(413, 'Solicitud demasiado grande');
  try { return raw ? JSON.parse(raw) : {}; } catch { fail(400, 'JSON inválido'); }
}

const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function requireRole(req, ...roles) {
  const u = await getSession(req);
  if (!u) fail(401, 'Sesión vencida. Volvé a ingresar.');
  if (!roles.includes(u.rol)) fail(403, 'No tenés permiso para esta acción');
  if (u.debe_cambiar) fail(403, 'Tenés que cambiar la contraseña antes de seguir');
  return u;
}

// ---------- formato de filas para el navegador ----------
const codigoOut = (r) => ({
  codigo: r.codigo, empresa: r.empresa, comprobante: r.comprobante, patente: r.patente,
  generado_en: r.generado_en, vence_en: r.vence_en, ingreso_en: r.ingreso_en, egreso_en: r.egreso_en,
  estadia_horas: r.estadia_horas, estado: r.estado, creador: r.creado_por, verifico: r.verifico, egreso_user: r.egreso_por,
});
const empresaOut = (e) => ({ id: e.id, nombre: e.nombre, cuit: e.cuit, apiEnabled: e.api_habilitada, apiTokenFin: e.api_token_fin });

// ---------- códigos ----------
const LETRAS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const DIGITOS = '23456789';
const CHARSET = LETRAS + DIGITOS;
function randomCode() {
  const pick = (set) => set[crypto.randomInt(set.length)];
  const chars = [pick(LETRAS), pick(DIGITOS)];
  while (chars.length < 6) chars.push(pick(CHARSET));
  for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- rutas ----------
const routes = {
  'GET /sesion': async (req) => {
    const u = await getSession(req);
    return { user: u ? { username: u.username, role: u.rol, debeCambiar: u.debe_cambiar } : null };
  },

  'POST /login': async (req, res, body) => {
    const rol = str(body.rol, 20);
    const username = str(body.username, 40).toLowerCase();
    const clave = typeof body.clave === 'string' ? body.clave.slice(0, 100) : '';
    if (!['admin', 'generador', 'verificador'].includes(rol)) fail(400, 'Rol inválido');
    const etiqueta = { admin: 'Admin', generador: 'Generador', verificador: 'Verificador' }[rol];
    const r = await checkCredentials(rol, username, clave);
    if (!r.ok) {
      await audit('sistema', 'sistema', `Login fallido (${etiqueta})`, `Intento con usuario "${username}"${r.bloqueado ? ' · usuario bloqueado' : ''}`);
      fail(401, r.motivo);
    }
    await setSessionCookie(res, r.user);
    await audit(r.user.username, rol, 'Login exitoso', `Sesión iniciada como ${etiqueta}`);
    return { user: { username: r.user.username, role: rol, debeCambiar: r.user.debe_cambiar } };
  },

  'POST /logout': async (req, res) => {
    const u = await getSession(req);
    if (u) await audit(u.username, u.rol, 'Logout', '');
    clearSessionCookie(res);
    return { ok: true };
  },

  'POST /cambiar-clave': async (req, res, body) => {
    const u = await getSession(req);
    if (!u) fail(401, 'Sesión vencida. Volvé a ingresar.');
    if (u.rol !== 'admin') fail(403, 'Los PIN no se modifican: pedí al administrador una cuenta nueva');
    const nueva = typeof body.nueva === 'string' ? body.nueva : '';
    if (nueva.length < 10) fail(400, 'La contraseña nueva debe tener al menos 10 caracteres');
    const r = await checkCredentials('admin', u.username, typeof body.actual === 'string' ? body.actual : '');
    if (!r.ok) fail(401, r.bloqueado ? r.motivo : 'La contraseña actual no es correcta');
    if (typeof body.actual === 'string' && body.actual === nueva) fail(400, 'La contraseña nueva tiene que ser distinta');
    await query(`UPDATE usuarios SET hash = $2, debe_cambiar = FALSE WHERE id = $1`, [u.id, await hashClave(nueva)]);
    await audit(u.username, u.rol, 'Contraseña cambiada', '');
    return { ok: true };
  },

  // Datos iniciales de cada pantalla, según el rol.
  'GET /datos': async (req) => {
    const u = await requireRole(req, 'admin', 'generador', 'verificador');
    const config = await getConfig();
    if (u.rol === 'generador') {
      const [empresas, stats] = await Promise.all([
        query(`SELECT id, nombre FROM empresas WHERE activa ORDER BY nombre`),
        one(`SELECT count(*) FILTER (WHERE estado IN ('Creado','En Sitio') AND (estado = 'En Sitio' OR vence_en > now()))::int AS activos,
                    count(*) FILTER (WHERE estado = 'En Sitio')::int AS en_sitio,
                    count(*) FILTER (WHERE estado = 'Finalizado')::int AS finalizados FROM codigos`),
      ]);
      return { config, empresas, stats };
    }
    if (u.rol === 'verificador') {
      const enSitio = await query(`SELECT * FROM codigos WHERE estado = 'En Sitio' ORDER BY ingreso_en`);
      return { config, enSitio: enSitio.map(codigoOut), ahora: new Date().toISOString() };
    }
    const [empresas, codigos, usuarios, auditoria] = await Promise.all([
      query(`SELECT * FROM empresas WHERE activa ORDER BY nombre`),
      query(`SELECT * FROM codigos ORDER BY generado_en DESC LIMIT 5000`),
      query(`SELECT id, username, rol, activo, bloqueado_hasta FROM usuarios WHERE rol <> 'admin' ORDER BY username`),
      query(`SELECT * FROM auditoria ORDER BY ts DESC, id DESC LIMIT 3000`),
    ]);
    const totalCodigos = (await one(`SELECT count(*)::int AS n FROM codigos`)).n;
    const uOut = (x) => ({ id: x.id, user: x.username, active: x.activo, bloqueado: !!(x.bloqueado_hasta && new Date(x.bloqueado_hasta) > new Date()) });
    return {
      config,
      empresas: empresas.map(empresaOut),
      codigos: codigos.map(codigoOut),
      totalCodigos,
      usuarios: {
        generadores: usuarios.filter((x) => x.rol === 'generador').map(uOut),
        verificadores: usuarios.filter((x) => x.rol === 'verificador').map(uOut),
      },
      auditLog: auditoria.map((a) => ({ ts: a.ts, user: a.usuario, role: a.rol, action: a.accion, details: a.detalle })),
    };
  },

  // ----- Generador -----
  'POST /codigos': async (req, res, body) => {
    const u = await requireRole(req, 'generador');
    const config = await getConfig();
    const cantidad = Number.parseInt(body.cantidad, 10);
    const comprobante = str(body.comprobante, 60);
    if (!(cantidad >= 1 && cantidad <= config.maxCodigosPorGeneracion)) fail(400, `La cantidad debe estar entre 1 y ${config.maxCodigosPorGeneracion}`);
    if (!comprobante) fail(400, 'Falta el número de comprobante');
    const empresa = await one(`SELECT id, nombre FROM empresas WHERE id = $1 AND activa`, [Number.parseInt(body.empresaId, 10) || 0]);
    if (!empresa) fail(400, 'Empresa inexistente');

    const r = await checkCredentials('generador', u.username, typeof body.pin === 'string' ? body.pin : '');
    if (!r.ok) {
      await audit(u.username, 'generador', 'Confirmación de generación fallida', `Usuario ${u.username}${r.bloqueado ? ' · usuario bloqueado' : ''}`);
      fail(401, r.bloqueado ? r.motivo : 'Clave personal incorrecta');
    }

    const venceEn = new Date(Date.now() + config.codigoValidezDias * 86400000);
    const creados = [];
    for (let intento = 0; creados.length < cantidad && intento < 10; intento++) {
      const lote = Array.from({ length: cantidad - creados.length }, randomCode);
      const rows = await query(
        `INSERT INTO codigos (codigo, empresa_id, empresa, comprobante, creado_por, vence_en, estadia_horas)
         SELECT c, $2, $3, $4, $5, $6, $7 FROM unnest($1::text[]) AS c
         ON CONFLICT (codigo) DO NOTHING RETURNING codigo`,
        [lote, empresa.id, empresa.nombre, comprobante, u.username, venceEn, config.estadiaHorasMax],
      );
      creados.push(...rows.map((x) => x.codigo));
    }
    if (creados.length < cantidad) fail(500, 'No se pudieron generar todos los códigos. Probá de nuevo.');
    await audit(u.username, 'generador', 'Código generado', `${creados.length} código(s) ${creados.join(', ')} · Empresa ${empresa.nombre} · Comprobante ${comprobante}`);
    return { codigos: creados, empresa: empresa.nombre, comprobante, venceEn, generadoEn: new Date(), estadiaHoras: config.estadiaHorasMax, validezDias: config.codigoValidezDias };
  },

  // ----- Verificador -----
  'POST /verificar': async (req, res, body) => {
    const u = await requireRole(req, 'verificador');
    const code = str(body.codigo, 12).toUpperCase();
    const c = await one(`SELECT * FROM codigos WHERE codigo = $1`, [code]);
    const rechazo = async (msg, det) => { await audit(u.username, 'verificador', 'Verificación rechazada', `Código ${code} ${det}`); return { state: 'rechazado', msg }; };
    if (!c) return rechazo('Código no encontrado', 'no encontrado');
    if (c.estado === 'Finalizado') return rechazo('Código ya utilizado', 'ya finalizado');
    if (c.estado === 'En Sitio') {
      await audit(u.username, 'verificador', 'Verificación aprobada (egreso)', `Código ${code}`);
      return { state: 'egreso_listo', code: codigoOut(c) };
    }
    if (new Date(c.vence_en) < new Date()) return rechazo('Código vencido', 'vencido');
    await audit(u.username, 'verificador', 'Verificación aprobada (ingreso)', `Código ${code}`);
    return { state: 'ingreso_listo', code: codigoOut(c) };
  },

  'POST /ingreso': async (req, res, body) => {
    const u = await requireRole(req, 'verificador');
    const code = str(body.codigo, 12).toUpperCase();
    const patente = str(body.patente, 20).toUpperCase().replace(/\s+/g, ' ');
    if (!/^[A-Z0-9][A-Z0-9 -]{3,11}$/.test(patente)) fail(400, 'Patente inválida: solo letras, números y espacios');
    const c = await one(
      `UPDATE codigos SET estado = 'En Sitio', patente = $2, ingreso_en = now(), verifico = $3
       WHERE codigo = $1 AND estado = 'Creado' AND vence_en > now() RETURNING *`,
      [code, patente, u.username],
    );
    if (!c) fail(409, 'El código ya no está disponible para ingreso (usado o vencido)');
    await audit(u.username, 'verificador', 'Ingreso registrado', `Código ${code} · Patente ${patente} · Empresa ${c.empresa}`);
    return { ok: true };
  },

  'POST /egreso': async (req, res, body) => {
    const u = await requireRole(req, 'verificador');
    const code = str(body.codigo, 12).toUpperCase();
    const c = await one(
      `UPDATE codigos SET estado = 'Finalizado', egreso_en = now(), egreso_por = $2
       WHERE codigo = $1 AND estado = 'En Sitio' RETURNING *`,
      [code, u.username],
    );
    if (!c) fail(409, 'Ese vehículo no figura en planta');
    const horas = (new Date(c.egreso_en) - new Date(c.ingreso_en)) / 3600000;
    const exceso = horas > c.estadia_horas ? ` · Excedió la estadía (${horas.toFixed(1)} h de ${c.estadia_horas} h)` : '';
    await audit(u.username, 'verificador', 'Egreso registrado', `Código ${code} · Patente ${c.patente} · Empresa ${c.empresa}${exceso}`);
    return { ok: true, excedido: !!exceso };
  },

  // Eventos que solo ocurren en el navegador (descargas) pero quedan en la auditoría.
  'POST /eventos': async (req, res, body) => {
    const u = await requireRole(req, 'admin', 'generador', 'verificador');
    const permitidas = ['PDF descargado', 'Exportación a Excel', 'Exportación de auditoría'];
    const accion = str(body.accion, 60);
    if (!permitidas.includes(accion)) fail(400, 'Evento desconocido');
    await audit(u.username, u.rol, accion, str(body.detalle, 300));
    return { ok: true };
  },

  // ----- Admin: empresas -----
  'POST /empresas': async (req, res, body) => {
    const u = await requireRole(req, 'admin');
    const nombre = str(body.nombre, 120);
    const cuit = str(body.cuit, 20);
    if (!nombre) fail(400, 'Falta el nombre');
    const dup = await one(`SELECT 1 FROM empresas WHERE activa AND lower(nombre) = lower($1)`, [nombre]);
    if (dup) fail(409, 'Ya existe una empresa con ese nombre');
    await query(`INSERT INTO empresas (nombre, cuit) VALUES ($1, $2)`, [nombre, cuit]);
    await audit(u.username, 'admin', 'Empresa creada', `${nombre} · CUIT ${cuit || '(sin CUIT)'}`);
    return { ok: true };
  },

  'PUT /empresas/:id': async (req, res, body, id) => {
    const u = await requireRole(req, 'admin');
    const r = await checkCredentials('admin', u.username, typeof body.claveAdmin === 'string' ? body.claveAdmin : '');
    const e = await one(`SELECT * FROM empresas WHERE id = $1 AND activa`, [id]);
    if (!e) fail(404, 'Empresa inexistente');
    if (!r.ok) {
      await audit(u.username, 'admin', 'Edición de empresa fallida', `Re-auth incorrecta · Empresa ${e.nombre}`);
      fail(401, r.bloqueado ? r.motivo : 'Contraseña de administrador incorrecta');
    }
    const nombre = str(body.nombre, 120) || e.nombre;
    const cuit = str(body.cuit, 20);
    const api = !!body.apiEnabled;
    let token = null;
    let tokenHash = e.api_token_hash, tokenFin = e.api_token_fin;
    if (api && (!e.api_habilitada || body.regenerarToken)) {
      token = 'sk_' + crypto.randomBytes(24).toString('hex');
      tokenHash = sha256(token); tokenFin = token.slice(-4);
    }
    if (!api) { tokenHash = null; tokenFin = null; }
    await query(
      `UPDATE empresas SET nombre = $2, cuit = $3, api_habilitada = $4, api_token_hash = $5, api_token_fin = $6 WHERE id = $1`,
      [id, nombre, cuit, api, tokenHash, tokenFin],
    );
    const antes = JSON.stringify({ nombre: e.nombre, cuit: e.cuit, apiEnabled: e.api_habilitada });
    const despues = JSON.stringify({ nombre, cuit, apiEnabled: api });
    await audit(u.username, 'admin', 'Empresa editada', `${nombre} · Antes: ${antes} · Después: ${despues}${token ? ' · Se generó un token de API nuevo' : ''}`);
    return { ok: true, token };
  },

  'DELETE /empresas/:id': async (req, res, body, id) => {
    const u = await requireRole(req, 'admin');
    const e = await one(`UPDATE empresas SET activa = FALSE, api_habilitada = FALSE, api_token_hash = NULL WHERE id = $1 AND activa RETURNING nombre`, [id]);
    if (!e) fail(404, 'Empresa inexistente');
    await audit(u.username, 'admin', 'Empresa eliminada', e.nombre);
    return { ok: true };
  },

  // ----- Admin: usuarios -----
  'POST /usuarios': async (req, res, body) => {
    const u = await requireRole(req, 'admin');
    const rol = str(body.rol, 20);
    const username = str(body.username, 40).toLowerCase();
    const pin = typeof body.pin === 'string' ? body.pin : '';
    if (!['generador', 'verificador'].includes(rol)) fail(400, 'Rol inválido');
    if (!/^[a-z0-9._-]{2,30}$/.test(username)) fail(400, 'Usuario inválido: usá letras, números, punto o guion (sin espacios)');
    if (!/^\d{6}$/.test(pin)) fail(400, 'El PIN debe tener exactamente 6 dígitos');
    if (/^(\d)\1{5}$/.test(pin) || ['123456', '654321', '012345', '123123'].includes(pin)) fail(400, 'PIN demasiado fácil de adivinar');
    const rows = await query(
      `INSERT INTO usuarios (username, rol, hash, creado_por) VALUES ($1, $2, $3, $4) ON CONFLICT (rol, username) DO NOTHING RETURNING id`,
      [username, rol, await hashClave(pin), u.username],
    );
    if (rows.length === 0) fail(409, 'Ya existe un usuario con ese nombre');
    await audit(u.username, 'admin', 'Usuario creado', `${rol} · ${username}`);
    return { ok: true };
  },

  'PUT /usuarios/:id': async (req, res, body, id) => {
    const u = await requireRole(req, 'admin');
    const activo = !!body.active;
    const t = await one(
      `UPDATE usuarios SET activo = $2, intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1 AND rol <> 'admin' RETURNING username, rol`,
      [id, activo],
    );
    if (!t) fail(404, 'Usuario inexistente');
    await audit(u.username, 'admin', activo ? 'Usuario habilitado' : 'Usuario deshabilitado', `${t.rol} · ${t.username}`);
    return { ok: true };
  },

  // ----- Admin: configuración -----
  'PUT /config': async (req, res, body) => {
    const u = await requireRole(req, 'admin');
    const antes = await getConfig();
    const int = (v, min, max, def) => { const n = Number.parseInt(v, 10); return n >= min && n <= max ? n : def; };
    const email = (v, def) => (typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) ? v.trim() : v === '' ? '' : def);
    const nueva = {
      codigoValidezDias: int(body.codigoValidezDias, 1, 365, antes.codigoValidezDias),
      estadiaHorasMax: int(body.estadiaHorasMax, 1, 240, antes.estadiaHorasMax),
      maxCodigosPorGeneracion: int(body.maxCodigosPorGeneracion, 1, 100, antes.maxCodigosPorGeneracion),
      headerTexto: str(body.headerTexto, 80) || antes.headerTexto,
      notifEmailTo: email(body.notifEmailTo, antes.notifEmailTo),
      notifEmailCc: email(body.notifEmailCc, antes.notifEmailCc),
      alertaEstadiaHoras: int(body.alertaEstadiaHoras, 1, 240, antes.alertaEstadiaHoras),
    };
    await query(`UPDATE config SET datos = $1 WHERE id = 1`, [JSON.stringify(nueva)]);
    await audit(u.username, 'admin', 'Configuración actualizada', `Antes: ${JSON.stringify(antes)} · Después: ${JSON.stringify(nueva)}`);
    return { config: nueva };
  },

  // ----- API externa para empresas habilitadas -----
  'GET /externo/codigos': async (req) => {
    const m = (req.headers.authorization || '').match(/^Bearer\s+(sk_[a-f0-9]{48})$/);
    if (!m) fail(401, 'Falta el token (Authorization: Bearer sk_...)');
    const e = await one(`SELECT id, nombre FROM empresas WHERE activa AND api_habilitada AND api_token_hash = $1`, [sha256(m[1])]);
    if (!e) fail(401, 'Token inválido');
    const rows = await query(
      `SELECT codigo, comprobante, estado, patente, generado_en, vence_en, ingreso_en, egreso_en FROM codigos
       WHERE empresa_id = $1 ORDER BY generado_en DESC LIMIT 500`, [e.id]);
    return { empresa: e.nombre, codigos: rows };
  },
};

export default async function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();
  try {
    // Protección CSRF: las escrituras solo se aceptan desde el propio sitio.
    if (method !== 'GET') {
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) fail(403, 'Origen no permitido');
    }
    let fn = routes[`${method} ${path}`];
    let id = null;
    if (!fn) {
      const m = path.match(/^\/(empresas|usuarios)\/(\d+)$/);
      if (m) { fn = routes[`${method} /${m[1]}/:id`]; id = Number(m[2]); }
    }
    if (!fn) fail(404, 'Ruta inexistente');
    const body = method === 'GET' || method === 'DELETE' ? {} : await readBody(req);
    send(res, 200, await fn(req, res, body, id));
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Error interno del servidor' });
  }
}
