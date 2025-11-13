export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const target = url.searchParams.get("url");
    const origin = request.headers.get("origin") || "";

    if (!target) return response(400, "Missing ?url=");

    // strict allowlists
    const allowedOrigins = ["https://proxy-worker.bitsonline.nl"];
    const allowedTargets = ["api.partner.io", "data.internal.net"];

    if (!allowedOrigins.includes(origin)) return response(403, "Origin not allowed");
    const targetHost = safeHost(target);
    if (!allowedTargets.includes(targetHost)) return response(403, "Target not allowed");

    // rate limit by origin per minute
    const rateKey = `rate-${origin}`;
    const count = parseInt((await env.RATE_LIMITS.get(rateKey)) || "0", 10);
    if (count > 300) return response(429, "Rate limit exceeded");
    await env.RATE_LIMITS.put(rateKey, (count + 1).toString(), { expirationTtl: 60 });

    // handle preflight early
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers: corsHeaders(origin) });

    const cache = caches.default;
    const cacheKey = new Request(url.toString(), request);
    const cached = await cache.match(cacheKey);

    if (cached) {
      log(env, origin, target, request.method, 200, "HIT");
      const r = new Response(cached.body, cached);
      r.headers.set("x-cache-status", "HIT");
      addCORS(r.headers, origin);
      return r;
    }

    // sanitize headers
    const newHeaders = new Headers(request.headers);
    for (const h of ["origin", "referer", "cf-connecting-ip", "x-real-ip", "x-forwarded-for"])
      newHeaders.delete(h);

    const upstream = await fetch(target, {
      method: request.method,
      headers: newHeaders,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual",
    });

    const respHeaders = new Headers(upstream.headers);
    addCORS(respHeaders, origin);
    respHeaders.set("x-cache-status", "MISS");

    const response = new Response(upstream.body, {
      status: upstream.status,
      headers: respHeaders,
    });

    // log event and cache successful GETs
    log(env, origin, target, request.method, upstream.status, "MISS");
    if (request.method === "GET" && upstream.ok) {
      response.headers.append("Cache-Control", "max-age=60");
      env.waitUntil(cache.put(cacheKey, response.clone()));
    }

    return response;
  },
};

function response(status, message) {
  return new Response(message, { status });
}

function safeHost(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

function corsHeaders(origin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "Origin, X-Requested-With, Content-Type, Accept, Authorization",
    "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  };
}

function addCORS(headers, origin) {
  const cors = corsHeaders(origin);
  for (const [k, v] of Object.entries(cors)) headers.set(k, v);
}

function log(env, origin, target, method, status, cache) {
  try {
    env.CORS_LOGS.writeDataPoint({
      blobs: [origin, target, method, status.toString(), cache],
      doubles: [status],
    });
  } catch (e) {
    console.log("Log write failed:", e);
  }
}
