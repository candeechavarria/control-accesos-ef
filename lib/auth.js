import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';
import { one, query } from './db.js';

const COOKIE = 'ca_sesion';
const SESION_HORAS = 12;
const MAX_INTENTOS = 5;
const BLOQUEO_MIN = 15;
let DUMMY_HASH = null;

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s) {
    if (process.env.VERCEL) throw new Error('Falta SESSION_SECRET en las variables de entorno.');
    return new TextEncoder().encode('solo-para-desarrollo-local');
  }
  return new TextEncoder().encode(s);
}

export async function setSessionCookie(res, user) {
  const token = await new SignJWT({ uid: user.id, rol: user.rol, username: user.username })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${SESION_HORAS}h`)
    .sign(secret());
  const secure = process.env.VERCEL ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESION_HORAS * 3600}${secure}`);
}

export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

// Lee la cookie y revalida contra la base: una baja o un bloqueo cortan el acceso al instante.
export async function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return null;
  try {
    const { payload } = await jwtVerify(m[1], secret());
    const u = await one(`SELECT id, username, rol, activo, debe_cambiar FROM usuarios WHERE id = $1`, [payload.uid]);
    if (!u || !u.activo) return null;
    return u;
  } catch {
    return null;
  }
}

// Verifica usuario + clave con bloqueo tras MAX_INTENTOS fallidos seguidos.
export async function checkCredentials(rol, username, clave) {
  const u = await one(`SELECT * FROM usuarios WHERE rol = $1 AND username = $2`, [rol, username]);
  if (!u || !u.activo) {
    DUMMY_HASH ??= await bcrypt.hash('x', 10);
    await bcrypt.compare(clave, DUMMY_HASH); // mismo tiempo de respuesta exista o no el usuario
    return { ok: false, motivo: 'Usuario o clave incorrectos' };
  }
  if (u.bloqueado_hasta && new Date(u.bloqueado_hasta) > new Date()) {
    const min = Math.ceil((new Date(u.bloqueado_hasta) - new Date()) / 60000);
    return { ok: false, bloqueado: true, motivo: `Usuario bloqueado por intentos fallidos. Probá de nuevo en ${min} min.` };
  }
  if (!(await bcrypt.compare(clave, u.hash))) {
    const intentos = u.intentos_fallidos + 1;
    const bloquear = intentos >= MAX_INTENTOS;
    await query(
      `UPDATE usuarios SET intentos_fallidos = $2, bloqueado_hasta = $3 WHERE id = $1`,
      [u.id, bloquear ? 0 : intentos, bloquear ? new Date(Date.now() + BLOQUEO_MIN * 60000) : null],
    );
    return {
      ok: false, user: u, bloqueado: bloquear,
      motivo: bloquear ? `Demasiados intentos. Usuario bloqueado ${BLOQUEO_MIN} min.` : 'Usuario o clave incorrectos',
    };
  }
  if (u.intentos_fallidos > 0 || u.bloqueado_hasta) {
    await query(`UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1`, [u.id]);
  }
  return { ok: true, user: u };
}

export const hashClave = (clave) => bcrypt.hash(clave, 10);
