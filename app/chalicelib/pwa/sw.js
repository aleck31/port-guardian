// tier-1 service worker (~/myners-lab/standards/PWA-INSTALLABLE.md): caches only the
// app shell as an offline fallback. API responses are never cached — they carry
// whitelist state that must not go stale or land on disk. Bump CACHE when SHELL changes.
const CACHE = 'port-guardian-shell-v1';

// '/api/' on the execute-api URL, '/' on the custom domain.
const BASE = new URL('./', self.location).pathname;
const SHELL = [
  '', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png',
  'icon-maskable-512.png', 'apple-touch-icon.png',
].map(p => BASE + p);

// API Gateway only base64-decodes a binary body when the first Accept type is binary,
// and a bare Request sends */*, so ask for PNGs explicitly or the cache stores base64 text.
const shellRequest = (u) =>
  new Request(u, { cache: 'reload', headers: u.endsWith('.png') ? { Accept: 'image/png' } : {} });

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      // allSettled: one failed asset must not stop the worker from installing
      .then(c => Promise.allSettled(SHELL.map(u => c.add(shellRequest(u)))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const { request } = e;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  // Cognito is cross-origin and every API route is outside SHELL: both bypass the worker.
  if (url.origin !== self.location.origin || !SHELL.includes(url.pathname)) return;

  // Network-first: the page carries server-injected config, so a fresh copy must win.
  e.respondWith(
    fetch(request)
      .then(res => {
        if (res.ok && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(request, copy));
        }
        return res;
      })
      .catch(async () => (await caches.match(request, { ignoreSearch: true })) || Response.error())
  );
});
