// Servidor local para probar sin Vercel: `npm run dev` → http://localhost:3000
// Sin DATABASE_URL usa PGlite en .data/. El primer admin toma la clave de INITIAL_ADMIN_PASSWORD.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import handler from './api/index.js';

const PORT = Number(process.env.PORT) || 3000;
const TYPES = { '.html': 'text/html; charset=utf-8', '.png': 'image/png', '.js': 'text/javascript', '.css': 'text/css' };

http.createServer(async (req, res) => {
  if (req.url.startsWith('/api/')) return handler(req, res);
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^([/\\])+/, '');
  if (path.startsWith('..')) { res.writeHead(404); return res.end('No encontrado'); }
  const file = join('public', path || 'index.html');
  try {
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404); res.end('No encontrado');
  }
}).listen(PORT, () => console.log(`Control de accesos en http://localhost:${PORT}`));
