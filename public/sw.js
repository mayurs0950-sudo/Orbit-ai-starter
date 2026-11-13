
"use strict";

const CACHE_NAME = "orbit-ai-cache-v1";

const APP_SHELL = [
  "/",
  "/manifest.json"
];

// Install
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      for (const url of APP_SHELL) {
        try {
          await cache.add(url);
        } catch (error) {
          console.warn("ORBIT cache skipped:", url, error);
        }
      }
    })
  );

  self.skipWaiting();
});

// Activate
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then(async (keys) => {
      await Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      );

      await self.clients.claim();
    })
  );
});

// Fetch
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Only handle GET requests from this origin.
  if (
    request.method !== "GET" ||
    url.origin !== self.location.origin
  ) {
    return;
  }

  // Never cache authentication, AI, or upload APIs.
  if (url.pathname.startsWith("/api/")) {
    return;
  }

  // Navigation: network first, cached app fallback.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();

            caches.open(CACHE_NAME).then((cache) => {
              cache.put("/", copy);
            });
          }

          return response;
        })
        .catch(async () => {
          return (
            await caches.match(request) ||
            await caches.match("/")
          );
        })
    );

    return;
  }

  // Static same-origin resources: cache first.
  event.respondWith(
    caches.match(request).then(async (cached) => {
      if (cached) {
        return cached;
      }

      try {
        const response = await fetch(request);

        if (response.ok && response.type === "basic") {
          const cache = await caches.open(CACHE_NAME);
          cache.put(request, response.clone());
        }

        return response;
      } catch (error) {
        return new Response("Resource unavailable offline.", {
          status: 503,
          headers: {
            "Content-Type": "text/plain"
          }
        });
      }
    })
  );
});

console.log("ORBIT AI Service Worker loaded");
