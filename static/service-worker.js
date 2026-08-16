const CACHE_NAME = "qafox-shell-v10";

const APP_SHELL = [
  "/",
  "/login",
  "/signup",
  "/static/app.css",
  "/static/app.js",
  "/static/manifest.webmanifest",
  "/static/icons/qafox-192.png",
  "/static/icons/qafox-512.png",
  "/static/offline.html"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches
      .keys()
      .then(keys =>
        Promise.all(
          keys
            .filter(key => key !== CACHE_NAME)
            .map(key => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;

  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);

  if (url.origin !== self.location.origin) {
    return;
  }

  if (
    url.pathname.startsWith("/dashboard") ||
    url.pathname.startsWith("/projects") ||
    url.pathname.startsWith("/verify-email") ||
    url.pathname.startsWith("/logout")
  ) {
    event.respondWith(fetch(request));
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() =>
        caches.match("/static/offline.html")
      )
    );
    return;
  }

  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) {
        return cached;
      }

      return fetch(request).then(response => {
        if (
          response.ok &&
          (
            url.pathname.startsWith("/static/") ||
            url.pathname === "/"
          )
        ) {
          const clone = response.clone();

          caches
            .open(CACHE_NAME)
            .then(cache => cache.put(request, clone));
        }

        return response;
      });
    })
  );
});
