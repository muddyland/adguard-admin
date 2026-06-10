// Minimal service worker: enables installability and offline app-shell.
// Strategy: never touch the API (network only); stale-while-revalidate for
// same-origin GETs (app shell + hashed assets, which are content-addressed).
const CACHE = 'agh-admin-v1'

self.addEventListener('install', () => self.skipWaiting())

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys()
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    await self.clients.claim()
  })())
})

self.addEventListener('fetch', (e) => {
  const req = e.request
  const url = new URL(req.url)
  // Only handle same-origin GETs; let the API and everything else hit the network.
  if (req.method !== 'GET' || url.origin !== location.origin) return
  if (url.pathname.startsWith('/api/')) return

  e.respondWith((async () => {
    const cache = await caches.open(CACHE)
    const cached = await cache.match(req)
    const network = fetch(req).then((res) => {
      if (res && res.status === 200 && res.type === 'basic') cache.put(req, res.clone())
      return res
    }).catch(() => cached)
    return cached || network
  })())
})
