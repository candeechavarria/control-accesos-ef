// Única función del servidor: todas las rutas /api/* llegan acá (ver vercel.json).
import crypto from 'node:crypto';
import { query, one, getConfig, audit } from '../lib/db.js';
import { checkCredentials, getSession, setSessionCookie, clearSessionCookie, hashClave } from '../lib/auth.js';
import { BASES_VERSION, basesTexto } from '../lib/bases.js';

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
  conductor: r.conductor, conductor_rol: r.conductor_rol, telefono: r.telefono, email: r.email,
  carnet_retenido: r.carnet_retenido, llave_bano: r.llave_bano,
  control_ok: r.control_ok, control_items: r.control_items, control_obs: r.control_obs,
  litros_cobrados: r.litros_cobrados == null ? null : Number(r.litros_cobrados),
  bases_aceptadas_en: r.bases_aceptadas_en, bases_version: r.bases_version, bases_via: r.bases_via,
});
const solicitudOut = (x) => ({
  id: x.id, creado_en: x.creado_en, origen: x.origen, empresa: x.empresa, patente: x.patente,
  conductor: x.conductor, conductor_rol: x.conductor_rol, telefono: x.telefono, email: x.email,
});
const itemOut = (x) => ({ id: x.id, descripcion: x.descripcion, litros: Number(x.litros) });

// ---------- datos del camión y del chofer ----------
const normPatente = (v) => str(v, 20).toUpperCase().replace(/[^A-Z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
// parcial = true: solo el dominio es obligatorio (el código se puede emitir antes de tener los datos).
function datosChofer(body, parcial = false) {
  const d = {
    empresa: str(body.empresa, 120),
    patente: normPatente(body.patente),
    conductor: str(body.conductor, 120),
    conductor_rol: str(body.conductorRol, 10),
    telefono: str(body.telefono, 30),
    email: str(body.email, 120).toLowerCase(),
  };
  if (!/^[A-Z0-9][A-Z0-9 ]{4,10}$/.test(d.patente)) fail(400, 'Dominio inválido: usá letras y números (ej. AB 123 CD)');
  if (!parcial || d.empresa || d.conductor || d.conductor_rol || d.telefono) {
    if (!d.empresa) fail(400, 'Falta la empresa');
    if (d.conductor.length < 3) fail(400, 'Falta el nombre y apellido');
    if (!['titular', 'chofer'].includes(d.conductor_rol)) fail(400, 'Indicá si es titular o chofer');
    if (!/^[+\d][\d\s()-]{6,}$/.test(d.telefono)) fail(400, 'Teléfono inválido');
  }
  if (d.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)) fail(400, 'Mail inválido');
  return d;
}
const ipHash = (req) => crypto.createHash('sha256')
  .update(String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim() + (process.env.SESSION_SECRET || ''))
  .digest('hex').slice(0, 32);

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

// Marca (una sola vez) los códigos que llevan más de N horas sin los datos del chofer y lo deja en auditoría.
async function marcarAvisosDatos(config) {
  const rows = await query(
    `UPDATE codigos SET aviso_datos_en = now()
     WHERE bases_aceptadas_en IS NULL AND aviso_datos_en IS NULL
       AND generado_en < now() - make_interval(hours => $1::int)
     RETURNING codigo, patente, creado_por`,
    [config.alertaDatosHoras],
  );
  for (const r of rows) {
    await audit('sistema', 'sistema', 'Aviso: código sin datos del chofer',
      `Código ${r.codigo} · Dominio ${r.patente} · Emitido por ${r.creado_por} · Pasaron más de ${config.alertaDatosHoras} h sin formulario QR ni papel firmado`);
  }
}
const PENDIENTES_SQL = `SELECT * FROM codigos WHERE bases_aceptadas_en IS NULL AND generado_en > now() - interval '30 days' ORDER BY generado_en`;

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

  // ----- Público: formulario del camionero (QR del cartel) -----
  'GET /publico': async () => {
    const config = await getConfig();
    return { whatsappSalida: config.whatsappSalida, bases: basesTexto(config) };
  },

  'POST /solicitudes': async (req, res, body) => {
    if (str(body.web, 50)) return { ok: true, numero: 0 }; // campo trampa: solo lo completan los robots
    const d = datosChofer(body);
    if (body.aceptaBases !== true) fail(400, 'Para enviar el formulario tenés que aceptar las bases y condiciones');
    if (body.basesVersion !== BASES_VERSION) fail(409, 'Las bases y condiciones se actualizaron. Recargá la página y volvé a aceptarlas.');
    const ip = ipHash(req);
    const recientes = await one(`SELECT count(*)::int AS n FROM solicitudes WHERE ip_hash = $1 AND creado_en > now() - interval '10 minutes'`, [ip]);
    if (recientes.n >= 20) fail(429, 'Demasiados envíos seguidos. Esperá unos minutos o avisá en la oficina.');
    const row = await one(
      `INSERT INTO solicitudes (origen, empresa, patente, conductor, conductor_rol, telefono, email, ip_hash, acepto_bases_en, bases_version)
       VALUES ('qr', $1, $2, $3, $4, $5, $6, $7, now(), $8) RETURNING id`,
      [d.empresa, d.patente, d.conductor, d.conductor_rol, d.telefono, d.email, ip, BASES_VERSION],
    );
    await audit('sistema', 'sistema', 'Formulario recibido (QR)', `Solicitud ${row.id} · Dominio ${d.patente} · Empresa ${d.empresa} · Aceptó bases y condiciones ${BASES_VERSION}`);
    const vinculado = await one(
      `UPDATE codigos SET empresa = $2, conductor = $3, conductor_rol = $4, telefono = $5, email = $6,
         bases_aceptadas_en = now(), bases_version = $7, bases_via = 'qr'
       WHERE id = (SELECT id FROM codigos WHERE replace(patente, ' ', '') = replace($1, ' ', '')
                     AND bases_aceptadas_en IS NULL AND estado IN ('Creado', 'En Sitio') ORDER BY generado_en DESC LIMIT 1)
       RETURNING codigo`,
      [d.patente, d.empresa, d.conductor, d.conductor_rol, d.telefono, d.email, BASES_VERSION],
    );
    if (vinculado) {
      await query(`UPDATE solicitudes SET estado = 'emitida', codigo = $2 WHERE id = $1`, [row.id, vinculado.codigo]);
      await audit('sistema', 'sistema', 'Datos completados por QR', `Código ${vinculado.codigo} · Dominio ${d.patente} · Solicitud ${row.id}`);
    }
    return { ok: true, numero: row.id, patente: d.patente, vinculado: !!vinculado };
  },

  // Datos iniciales de cada pantalla, según el rol.
  'GET /datos': async (req) => {
    const u = await requireRole(req, 'admin', 'generador', 'verificador');
    const config = await getConfig();
    await marcarAvisosDatos(config);
    if (u.rol === 'generador') {
      const [solicitudes, pendientes, empresas, stats] = await Promise.all([
        query(`SELECT * FROM solicitudes WHERE estado = 'pendiente' AND creado_en > now() - interval '24 hours' ORDER BY creado_en`),
        query(PENDIENTES_SQL),
        query(`SELECT empresa FROM codigos GROUP BY empresa ORDER BY max(generado_en) DESC LIMIT 300`),
        one(`SELECT count(*) FILTER (WHERE estado IN ('Creado','En Sitio') AND (estado = 'En Sitio' OR vence_en > now()))::int AS activos,
                    count(*) FILTER (WHERE estado = 'En Sitio')::int AS en_sitio,
                    count(*) FILTER (WHERE estado = 'Finalizado')::int AS finalizados FROM codigos`),
      ]);
      return { config, stats, solicitudes: solicitudes.map(solicitudOut), pendientes: pendientes.map(codigoOut), empresas: empresas.map((x) => x.empresa).filter(Boolean), ahora: new Date().toISOString() };
    }
    if (u.rol === 'verificador') {
      const [enSitio, items] = await Promise.all([
        query(`SELECT * FROM codigos WHERE estado = 'En Sitio' ORDER BY ingreso_en`),
        query(`SELECT * FROM control_items WHERE activo ORDER BY orden, id`),
      ]);
      return { config, enSitio: enSitio.map(codigoOut), controlItems: items.map(itemOut), ahora: new Date().toISOString() };
    }
    const [items, codigos, usuarios, auditoria, pendientes] = await Promise.all([
      query(`SELECT * FROM control_items WHERE activo ORDER BY orden, id`),
      query(`SELECT * FROM codigos ORDER BY generado_en DESC LIMIT 5000`),
      query(`SELECT id, username, rol, activo, bloqueado_hasta FROM usuarios WHERE rol <> 'admin' ORDER BY username`),
      query(`SELECT * FROM auditoria ORDER BY ts DESC, id DESC LIMIT 3000`),
      query(PENDIENTES_SQL),
    ]);
    const totalCodigos = (await one(`SELECT count(*)::int AS n FROM codigos`)).n;
    const uOut = (x) => ({ id: x.id, user: x.username, active: x.activo, bloqueado: !!(x.bloqueado_hasta && new Date(x.bloqueado_hasta) > new Date()) });
    return {
      config,
      controlItems: items.map(itemOut),
      pendientes: pendientes.map(codigoOut),
      ahora: new Date().toISOString(),
      codigos: codigos.map(codigoOut),
      totalCodigos,
      usuarios: {
        generadores: usuarios.filter((x) => x.rol === 'generador').map(uOut),
        verificadores: usuarios.filter((x) => x.rol === 'verificador').map(uOut),
      },
      auditLog: auditoria.map((a) => ({ ts: a.ts, user: a.usuario, role: a.rol, action: a.accion, details: a.detalle })),
    };
  },

  // Liviano: solo los códigos sin datos del chofer (el panel lo consulta cada minuto para el aviso).
  'GET /pendientes': async (req) => {
    await requireRole(req, 'admin', 'generador');
    const config = await getConfig();
    await marcarAvisosDatos(config);
    const rows = await query(PENDIENTES_SQL);
    return { pendientes: rows.map(codigoOut), alertaDatosHoras: config.alertaDatosHoras, ahora: new Date().toISOString() };
  },

  // ----- Generador -----
  'POST /solicitudes/:id/descartar': async (req, res, body, id) => {
    const u = await requireRole(req, 'generador');
    const x = await one(`UPDATE solicitudes SET estado = 'descartada' WHERE id = $1 AND estado = 'pendiente' RETURNING patente`, [id]);
    if (!x) fail(404, 'La solicitud ya no está pendiente');
    await audit(u.username, 'generador', 'Solicitud descartada', `Solicitud ${id} · Dominio ${x.patente}`);
    return { ok: true };
  },

  // Emite UN código para un camión, con los datos del formulario (QR o papel).
  'POST /codigos': async (req, res, body) => {
    const u = await requireRole(req, 'generador');
    const config = await getConfig();
    let d = datosChofer(body, true);
    const comprobante = str(body.comprobante, 60);
    if (!comprobante) fail(400, 'Falta el número de comprobante');
    const solicitudId = Number.parseInt(body.solicitudId, 10) || null;
    let bases = { en: null, version: null, via: null }; // sin bases = datos pendientes
    if (solicitudId) {
      const sol = await one(`SELECT estado, acepto_bases_en, bases_version FROM solicitudes WHERE id = $1`, [solicitudId]);
      if (!sol || sol.estado !== 'pendiente') fail(409, 'Esa solicitud ya fue atendida');
      d = datosChofer(body);
      bases = { en: sol.acepto_bases_en, version: sol.bases_version, via: 'qr' };
    } else if (body.firmoPapel === true) {
      d = datosChofer(body);
      bases = { en: new Date(), version: BASES_VERSION, via: 'papel' };
    }
    const enPlanta = await one(`SELECT codigo FROM codigos WHERE replace(patente, ' ', '') = replace($1, ' ', '') AND estado = 'En Sitio'`, [d.patente]);
    if (enPlanta) fail(409, `El dominio ${d.patente} figura adentro del playón (código ${enPlanta.codigo}). Registrá su egreso antes.`);

    const r = await checkCredentials('generador', u.username, typeof body.pin === 'string' ? body.pin : '');
    if (!r.ok) {
      await audit(u.username, 'generador', 'Confirmación de generación fallida', `Usuario ${u.username}${r.bloqueado ? ' · usuario bloqueado' : ''}`);
      fail(401, r.bloqueado ? r.motivo : 'Clave personal incorrecta');
    }

    const venceEn = new Date(Date.now() + config.codigoValidezDias * 86400000);
    let codigo = null;
    for (let intento = 0; !codigo && intento < 10; intento++) {
      const row = await one(
        `INSERT INTO codigos (codigo, empresa, comprobante, creado_por, vence_en, estadia_horas, patente, conductor, conductor_rol, telefono, email,
                              bases_aceptadas_en, bases_version, bases_via)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (codigo) DO NOTHING RETURNING codigo`,
        [randomCode(), d.empresa, comprobante, u.username, venceEn, config.estadiaHorasMax, d.patente, d.conductor, d.conductor_rol, d.telefono, d.email,
          bases.en, bases.version, bases.via],
      );
      codigo = row?.codigo ?? null;
    }
    if (!codigo) fail(500, 'No se pudo generar el código. Probá de nuevo.');
    if (solicitudId) {
      await query(`UPDATE solicitudes SET estado = 'emitida', codigo = $2, empresa = $3, patente = $4 WHERE id = $1`, [solicitudId, codigo, d.empresa, d.patente]);
    } else if (bases.via === 'papel') {
      await query(
        `INSERT INTO solicitudes (origen, empresa, patente, conductor, conductor_rol, telefono, email, estado, codigo, acepto_bases_en, bases_version)
         VALUES ('papel', $1, $2, $3, $4, $5, $6, 'emitida', $7, now(), $8)`,
        [d.empresa, d.patente, d.conductor, d.conductor_rol, d.telefono, d.email, codigo, BASES_VERSION],
      );
    }
    await audit(u.username, 'generador', 'Código generado',
      bases.via
        ? `${codigo} · Dominio ${d.patente} · ${d.conductor} (${d.conductor_rol}) · Empresa ${d.empresa} · Comprobante ${comprobante} · Formulario ${solicitudId ? 'QR' : 'papel firmado'} · Bases ${bases.version}`
        : `${codigo} · Dominio ${d.patente} · Comprobante ${comprobante} · Datos y bases pendientes`);
    return {
      codigos: [codigo], empresa: d.empresa, patente: d.patente, conductor: d.conductor, conductorRol: d.conductor_rol,
      comprobante, venceEn, generadoEn: new Date(), estadiaHoras: config.estadiaHorasMax, validezDias: config.codigoValidezDias,
      whatsappSalida: config.whatsappSalida, datosPendientes: !bases.via,
    };
  },

  // Completa los datos de un código emitido solo con el dominio, con el formulario en papel firmado.
  // (Si el chofer completa el QR, se completa solo: ver POST /solicitudes.)
  'PUT /codigos/:codigo/datos': async (req, res, body, codigo) => {
    const u = await requireRole(req, 'generador');
    const c = await one(`SELECT * FROM codigos WHERE codigo = $1`, [codigo]);
    if (!c) fail(404, 'Código inexistente');
    if (c.bases_aceptadas_en) fail(409, 'Ese código ya tiene los datos completos');
    const d = datosChofer({ ...body, patente: c.patente });
    if (body.firmoPapel !== true) fail(400, 'Confirmá que el chofer firmó el formulario en papel con las bases y condiciones');
    const comprobante = str(body.comprobante, 60) || c.comprobante;
    await query(
      `UPDATE codigos SET empresa = $2, conductor = $3, conductor_rol = $4, telefono = $5, email = $6, comprobante = $7,
         bases_aceptadas_en = now(), bases_version = $8, bases_via = 'papel' WHERE codigo = $1`,
      [codigo, d.empresa, d.conductor, d.conductor_rol, d.telefono, d.email, comprobante, BASES_VERSION],
    );
    await query(
      `INSERT INTO solicitudes (origen, empresa, patente, conductor, conductor_rol, telefono, email, estado, codigo, acepto_bases_en, bases_version)
       VALUES ('papel', $1, $2, $3, $4, $5, $6, 'emitida', $7, now(), $8)`,
      [d.empresa, c.patente, d.conductor, d.conductor_rol, d.telefono, d.email, codigo, BASES_VERSION],
    );
    await audit(u.username, 'generador', 'Datos completados (papel firmado)', `Código ${codigo} · Dominio ${c.patente} · ${d.conductor} (${d.conductor_rol}) · Empresa ${d.empresa}`);
    return { ok: true };
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
    // Sin formulario asociado (QR o papel firmado) el código todavía no sirve para entrar.
    if (!c.bases_aceptadas_en) {
      await audit(u.username, 'verificador', 'Ingreso frenado: sin formulario', `Código ${code} · Dominio ${c.patente}`);
      return { state: 'sin_formulario', code: codigoOut(c) };
    }
    await audit(u.username, 'verificador', 'Verificación aprobada (ingreso)', `Código ${code}`);
    return { state: 'ingreso_listo', code: codigoOut(c) };
  },

  // Antes de dejarlo pasar: se retiene el carnet y se entrega una llave del baño.
  'POST /ingreso': async (req, res, body) => {
    const u = await requireRole(req, 'verificador');
    const code = str(body.codigo, 12).toUpperCase();
    const llave = str(body.llave, 10).toUpperCase();
    if (body.carnet !== true) fail(400, 'Antes de dejarlo pasar hay que controlar y retener el carnet de conducir');
    if (!llave) fail(400, 'Indicá el número de llave del baño que entregaste');
    const ocupada = await one(`SELECT patente FROM codigos WHERE estado = 'En Sitio' AND llave_bano = $1`, [llave]);
    if (ocupada) fail(409, `La llave ${llave} figura entregada al dominio ${ocupada.patente}, que sigue en el playón`);
    const c = await one(
      `UPDATE codigos SET estado = 'En Sitio', ingreso_en = now(), verifico = $2, carnet_retenido = TRUE, llave_bano = $3
       WHERE codigo = $1 AND estado = 'Creado' AND vence_en > now() AND bases_aceptadas_en IS NOT NULL RETURNING *`,
      [code, u.username, llave],
    );
    if (!c) {
      const x = await one(`SELECT bases_aceptadas_en FROM codigos WHERE codigo = $1`, [code]);
      if (x && !x.bases_aceptadas_en) fail(409, 'Falta el formulario del chofer: no puede ingresar hasta completarlo (QR o papel firmado)');
      fail(409, 'El código ya no está disponible para ingreso (usado o vencido)');
    }
    await audit(u.username, 'verificador', 'Ingreso registrado',
      `Código ${code} · Dominio ${c.patente} · Empresa ${c.empresa} · Carnet de ${c.conductor} (${c.conductor_rol}) controlado y retenido · Llave de baño ${llave}`);
    return { ok: true };
  },

  // Salida: el supervisor revisa el baño. Si hay algo mal se cobra en litros según la tabla,
  // y recién entonces se devuelve el carnet.
  'POST /egreso': async (req, res, body) => {
    const u = await requireRole(req, 'verificador');
    const code = str(body.codigo, 12).toUpperCase();
    const ids = Array.isArray(body.items) ? body.items.map((x) => Number.parseInt(x, 10)).filter((x) => x > 0).slice(0, 50) : [];
    const obs = str(body.obs, 500);
    const items = ids.length ? await query(`SELECT * FROM control_items WHERE activo AND id = ANY($1::int[])`, [ids]) : [];
    if (items.length !== ids.length) fail(409, 'La tabla de control cambió. Recargá la página.');
    const hayTabla = (await one(`SELECT count(*)::int AS n FROM control_items WHERE activo`)).n > 0;
    let litros = items.reduce((t, x) => t + Number(x.litros), 0);
    if (!hayTabla) {
      const manual = Number(body.litrosManual);
      if (Number.isFinite(manual) && manual > 0) litros = Math.min(manual, 100000);
    }
    litros = Math.round(litros * 100) / 100;
    if (litros > 0 && body.cobrado !== true) fail(400, `Hay que cobrar ${litros} litros antes de devolver el carnet`);
    if (body.carnetDevuelto !== true) fail(400, 'Confirmá que devolviste el carnet');
    const snapshot = JSON.stringify(items.map((x) => ({ descripcion: x.descripcion, litros: Number(x.litros) })));
    const c = await one(
      `UPDATE codigos SET estado = 'Finalizado', egreso_en = now(), egreso_por = $2,
         control_ok = $3, control_items = $4::jsonb, control_obs = $5, litros_cobrados = $6
       WHERE codigo = $1 AND estado = 'En Sitio' RETURNING *`,
      [code, u.username, litros === 0 && items.length === 0, snapshot, obs || null, litros],
    );
    if (!c) fail(409, 'Ese vehículo no figura en el playón');
    const horas = (new Date(c.egreso_en) - new Date(c.ingreso_en)) / 3600000;
    const exceso = horas > c.estadia_horas ? ` · Excedió la estadía (${horas.toFixed(1)} h de ${c.estadia_horas} h)` : '';
    const control = litros > 0
      ? ` · Baño con observaciones: ${items.map((x) => x.descripcion).join(', ') || 'ver observaciones'} · Cobrado: ${litros} litros`
      : ' · Baño en orden';
    await audit(u.username, 'verificador', 'Egreso registrado',
      `Código ${code} · Dominio ${c.patente} · Empresa ${c.empresa} · Llave ${c.llave_bano || '-'} recibida · Carnet devuelto${control}${obs ? ` · Obs: ${obs}` : ''}${exceso}`);
    return { ok: true, excedido: !!exceso, litros };
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

  // ----- Admin: tabla de control del baño -----
  'PUT /control-items': async (req, res, body) => {
    const u = await requireRole(req, 'admin');
    const lista = Array.isArray(body.items) ? body.items.slice(0, 50) : fail(400, 'Lista inválida');
    const limpia = lista.map((x, i) => {
      const descripcion = str(x?.descripcion, 120);
      const litros = Number(x?.litros);
      if (!descripcion) fail(400, `Falta la descripción en la fila ${i + 1}`);
      if (!Number.isFinite(litros) || litros < 0 || litros > 100000) fail(400, `Litros inválidos en la fila ${i + 1}`);
      return { descripcion, litros: Math.round(litros * 100) / 100 };
    });
    await query(`UPDATE control_items SET activo = FALSE WHERE activo`);
    for (const [i, x] of limpia.entries()) {
      await query(`INSERT INTO control_items (descripcion, litros, orden) VALUES ($1, $2, $3)`, [x.descripcion, x.litros, i]);
    }
    await audit(u.username, 'admin', 'Tabla de control actualizada', limpia.map((x) => `${x.descripcion}: ${x.litros} L`).join(' · ') || '(vacía)');
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
      alertaDatosHoras: int(body.alertaDatosHoras, 1, 72, antes.alertaDatosHoras),
      whatsappSalida: typeof body.whatsappSalida === 'string' && /^[+\d][\d\s()-]{6,24}$|^$/.test(body.whatsappSalida.trim())
        ? body.whatsappSalida.trim() : antes.whatsappSalida,
    };
    await query(`UPDATE config SET datos = $1 WHERE id = 1`, [JSON.stringify(nueva)]);
    await audit(u.username, 'admin', 'Configuración actualizada', `Antes: ${JSON.stringify(antes)} · Después: ${JSON.stringify(nueva)}`);
    return { config: nueva };
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
      const m = path.match(/^\/(usuarios|solicitudes)\/(\d+)(\/descartar)?$/);
      if (m) { fn = routes[`${method} /${m[1]}/:id${m[3] || ''}`]; id = Number(m[2]); }
      const mc = path.match(/^\/codigos\/([A-Za-z0-9]{6})\/datos$/);
      if (mc) { fn = routes[`${method} /codigos/:codigo/datos`]; id = mc[1].toUpperCase(); }
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
