
"use strict";

/* =========================================
   ORBIT AI — PRODUCTION SERVICE WORKER
   ========================================= */

const CACHE_NAME = "orbit-ai-cache-v2";

const APP_SHELL = [
  "/",
  "/manifest.json"
];

/* INSTALL */
self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);

      for (const url of APP_SHELL) {
        try {
          await cache.add(url);
        } catch (error) {
          console.warn("ORBIT cache skipped:", url, error);
        }
      }

      await self.skipWaiting();
    })()
  );
});

/* ACTIVATE */
self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();

      await Promise.all(
        keys
          .filter(
            (key) =>
              key.startsWith("orbit-ai-cache-") &&
              key !== CACHE_NAME
          )
          .map((key) => caches.delete(key))
      );

      await self.clients.claim();
    })()
  );
});

/* FETCH */
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (
    request.method !== "GET" ||
    url.origin !== self.location.origin
  ) {
    return;
  }

  /* Never cache API, authentication or uploads */
  if (url.pathname.startsWith("/api/")) {
    return;
  }

  /* Navigation: Network First */
  if (request.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const response = await fetch(request);

          if (response.ok) {
            const cache = await caches.open(CACHE_NAME);
            await cache.put("/", response.clone());
          }

          return response;
        } catch (error) {
          return (
            (await caches.match(request)) ||
            (await caches.match("/")) ||
            new Response("ORBIT AI is currently unavailable offline.", {
              status: 503,
              headers: {
                "Content-Type": "text/plain; charset=utf-8"
              }
            })
          );
        }
      })()
    );

    return;
  }

  /* Static resources: Cache First */
  event.respondWith(
    (async () => {
      const cached = await caches.match(request);

      if (cached) {
        return cached;
      }

      try {
        const response = await fetch(request);

        if (response.ok && response.type === "basic") {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(request, response.clone());
        }

        return response;
      } catch (error) {
        return new Response("Resource unavailable offline.", {
          status: 503,
          headers: {
            "Content-Type": "text/plain; charset=utf-8"
          }
        });
      }
    })()
  );
});

console.log("ORBIT AI Service Worker v2 loaded");
