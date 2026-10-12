// Decrypts the protected site on the fly: a request inside the scope maps to _enc/<sha256(path)>.bin, which is
// AES-GCM-decrypted with the key the gate stored after the password was entered. Without a valid key every request
// passes through untouched, so the visitor sees the gate.
const SCOPE = new URL(self.registration.scope).pathname;
const OPEN = new Set(['sw.js', 's.bin', 'impressum.html']);
const TTL = 12 * 3600 * 1000; // stay unlocked for 12 h
const TYPES = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript',
  mjs: 'text/javascript',
  css: 'text/css',
  json: 'application/json',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  gif: 'image/gif',
  ico: 'image/x-icon',
  woff2: 'font/woff2',
  woff: 'font/woff',
  ttf: 'font/ttf',
  mp4: 'video/mp4',
  webm: 'video/webm',
  pdf: 'application/pdf',
  txt: 'text/plain; charset=utf-8',
  xml: 'application/xml',
};

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// ---- key store (IndexedDB survives the worker being stopped between requests)
const db = () =>
  new Promise((ok, no) => {
    const r = indexedDB.open('gate', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
const store = async (mode, fn) => {
  const d = await db();
  return new Promise((ok, no) => {
    const t = d.transaction('k', mode);
    const req = fn(t.objectStore('k'));
    t.oncomplete = () => ok(req.result);
    t.onerror = () => no(t.error);
  });
};
let keyP = null;
const files = new Map(); // path → Promise<ArrayBuffer | null>, decrypted once per worker lifetime
const getKey = () =>
  (keyP ??= store('readonly', (s) => s.get('key'))
    .then((v) => (v && v.exp > Date.now() ? crypto.subtle.importKey('raw', v.raw, 'AES-GCM', false, ['decrypt']) : null))
    .catch(() => null));
const forget = () => {
  keyP = null;
  files.clear();
  return store('readwrite', (s) => s.delete('key')).catch(() => {});
};

self.addEventListener('message', (e) => {
  const reply = () => e.ports[0] && e.ports[0].postMessage('ok');
  if (e.data && e.data.type === 'key')
    e.waitUntil(
      store('readwrite', (s) => s.put({raw: e.data.raw, exp: Date.now() + TTL}, 'key')).then(() => {
        keyP = null;
        files.clear();
        reply();
      }),
    );
  if (e.data && e.data.type === 'lock') e.waitUntil(forget().then(reply));
});

// ---- serving
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const load = (path, key) => {
  if (!files.has(path)) {
    const p = (async () => {
      const name = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(path))).slice(0, 32);
      const r = await fetch(SCOPE + '_enc/' + name + '.bin');
      if (!r.ok) return null;
      const b = new Uint8Array(await r.arrayBuffer());
      return crypto.subtle.decrypt({name: 'AES-GCM', iv: b.slice(0, 12)}, key, b.slice(12));
    })();
    files.set(path, p);
    p.catch(() => files.delete(path));
  }
  return files.get(path);
};

const serve = async (req, u) => {
  const key = await getKey();
  if (!key) return fetch(req);
  let path = decodeURIComponent(u.pathname).normalize('NFC');
  if (path.endsWith('/')) path += 'index.html';
  try {
    const body = await load(path, key);
    if (!body) {
      // /kontakt → /kontakt/ like a static host would
      if (!/\.[a-z0-9]+$/i.test(path) && (await load(path + '/index.html', key))) return Response.redirect(new URL(u.pathname + '/' + u.search, u).href, 301);
      const nf = req.mode === 'navigate' ? await load(SCOPE + '404.html', key) : null;
      return nf ? new Response(nf, {status: 404, headers: {'content-type': TYPES.html}}) : new Response('', {status: 404});
    }
    const type = TYPES[(path.split('.').pop() || '').toLowerCase()] || 'application/octet-stream';
    const size = body.byteLength;
    const range = /bytes=(\d*)-(\d*)/.exec(req.headers.get('range') || '');
    if (range) {
      // media seeking (the film) needs partial responses
      let a = range[1] ? +range[1] : size - +range[2];
      let z = range[1] && range[2] ? +range[2] : size - 1;
      z = Math.min(z, size - 1);
      return new Response(body.slice(a, z + 1), {status: 206, headers: {'content-type': type, 'content-range': `bytes ${a}-${z}/${size}`, 'content-length': String(z - a + 1), 'accept-ranges': 'bytes'}});
    }
    return new Response(body, {headers: {'content-type': type, 'content-length': String(size), 'accept-ranges': 'bytes'}});
  } catch (err) {
    // wrong or outdated key (e.g. the password was changed): forget it, the gate shows again
    await forget();
    return fetch(req);
  }
};

self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET' || !u.pathname.startsWith(SCOPE)) return;
  const rel = u.pathname.slice(SCOPE.length);
  if (OPEN.has(rel) || rel.startsWith('_enc/')) return;
  e.respondWith(serve(e.request, u));
});
