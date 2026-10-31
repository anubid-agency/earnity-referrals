/**
 * earnity-referrals — Cloudflare Worker
 * Referral visits, price requests, referee discounts, attribution and notifications.
 *
 * Bindings: DB (D1), FIREBASE_PROJECT_ID, HASH_SALT, INTERNAL_KEY
 * Deployed via GitHub → Cloudflare Workers Builds.
 */

const JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const ALLOWED_HOST = 'earnityug.com';

const LINK_CREDIT_SECONDS = 7 * 86400;
const REQUEST_VALID_SECONDS = 3 * 86400;
const DISCOUNT_VALID_SECONDS = 86400;
const SELF_REFERRAL_KEEP_BPS = 8000;
const MAX_MESSAGE_LENGTH = 200;
const MAX_BODY_BYTES = 4096;
const MAX_ID_LENGTH = 128;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_SECONDS = 3600;
const KEY_CACHE_MS = 3600_000;
const MAX_SUB_LENGTH = 128;

const VISITOR_ID_RE = /^[A-Za-z0-9_\-]{22,36}$/;

const enc = new TextEncoder();

let jwksMem = { keys: null, expires: 0 };
const keyMem = new Map();
let hmacKeyCache = { salt: null, key: null };
let lastForced = 0;

class HttpError extends Error {
  constructor(status, code, extra) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function json(data, status, cors, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...cors,
      ...extraHeaders,
    },
  });
}

function corsHeaders(origin) {
  if (!origin) return { Vary: 'Origin' };
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Visitor-Id',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return (
      u.protocol === 'https:' &&
      (u.hostname === ALLOWED_HOST || u.hostname.endsWith('.' + ALLOWED_HOST))
    );
  } catch {
    return false;
  }
}

function assertEnv(env, names) {
  for (const name of names) {
    if (!env[name]) {
      console.error('missing_env', { name });
      throw new HttpError(500, 'server_misconfigured');
    }
  }
}

function generateId(prefix) {
  const rand = crypto.getRandomValues(new Uint8Array(8));
  return (
    prefix +
    Date.now().toString(36) +
    Array.from(rand)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function b64urlDecode(input) {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function readJson(request) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (ct !== 'application/json' && !ct.startsWith('application/json;')) {
    throw new HttpError(415, 'unsupported_media_type');
  }
  const len = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
    throw new HttpError(413, 'payload_too_large');
  }
  const text = await request.text();
  if (enc.encode(text).length > MAX_BODY_BYTES) {
    throw new HttpError(413, 'payload_too_large');
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'invalid_json');
  }
  return data;
}

async function hmacHex(env, message) {
  let key = hmacKeyCache.key;
  if (!key || hmacKeyCache.salt !== env.HASH_SALT) {
    key = await crypto.subtle.importKey(
      'raw',
      enc.encode(env.HASH_SALT),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    hmacKeyCache = { salt: env.HASH_SALT, key };
  }
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(sig);
}

async function getJwks(env, force) {
  const now = Date.now();
  if (!force && jwksMem.keys && jwksMem.expires > now) return jwksMem.keys;
  const res = await fetch(
    JWKS_URL,
    force
      ? { cache: 'no-store', cf: { cacheTtl: 0, cacheEverything: false } }
      : { cf: { cacheTtl: JWKS_CACHE_SECONDS, cacheEverything: true } }
  );
  if (!res.ok) throw new Error('jwks_fetch_failed');
  const data = await res.json();
  if (!Array.isArray(data.keys)) throw new Error('jwks_invalid');
  jwksMem = { keys: data.keys, expires: now + JWKS_CACHE_SECONDS * 1000 };
  return data.keys;
}

async function importJwk(jwk) {
  const cached = keyMem.get(jwk.kid);
  if (cached && cached.expires > Date.now()) return cached.key;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  keyMem.set(jwk.kid, { key, expires: Date.now() + KEY_CACHE_MS });
  return key;
}

async function getKey(kid, env) {
  let keys = await getJwks(env, false);
  let jwk = keys.find((k) => k.kid === kid);
  if (!jwk) {
    const now = Date.now();
    if (now - lastForced >= 60000) {
      lastForced = now;
      keys = await getJwks(env, true);
      jwk = keys.find((k) => k.kid === kid);
    }
  }
  if (!jwk) throw new Error('key_not_found');
  return importJwk(jwk);
}

async function verifyFirebaseToken(token, env, now) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed');
  const [headerPart, payloadPart, sigPart] = parts;
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerPart)));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
    throw new Error('alg');
  }
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadPart)));
  const key = await getKey(header.kid, env);
  const data = enc.encode(`${headerPart}.${payloadPart}`);
  const sig = b64urlDecode(sigPart);
  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    sig,
    data
  );
  if (!valid) throw new Error('signature');
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now) {
    throw new Error('exp');
  }
  if (
    typeof payload.iat !== 'number' ||
    !Number.isFinite(payload.iat) ||
    payload.iat > now + CLOCK_SKEW_SECONDS
  ) {
    throw new Error('iat');
  }
  if (
    typeof payload.auth_time !== 'number' ||
    !Number.isFinite(payload.auth_time) ||
    payload.auth_time > now + CLOCK_SKEW_SECONDS
  ) {
    throw new Error('auth_time');
  }
  if (payload.aud !== env.FIREBASE_PROJECT_ID) throw new Error('aud');
  if (payload.iss !== `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`) {
    throw new Error('iss');
  }
  if (
    typeof payload.sub !== 'string' ||
    !payload.sub ||
    payload.sub.length > MAX_SUB_LENGTH
  ) {
    throw new Error('sub');
  }
  return payload;
}

async function requireAuth(request, env, now) {
  const auth = request.headers.get('Authorization');
  if (!auth) throw new HttpError(401, 'unauthorized');
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new HttpError(401, 'unauthorized');
  let payload;
  try {
    payload = await verifyFirebaseToken(match[1], env, now);
  } catch {
    throw new HttpError(401, 'invalid_token');
  }
  const user = await env.DB.prepare(
    'SELECT id, firebase_uid, display_name, account_type, status FROM users WHERE firebase_uid = ? LIMIT 1'
  )
    .bind(payload.sub)
    .first();
  if (!user) throw new HttpError(404, 'not_registered');
  if (user.status === 'blocked') throw new HttpError(403, 'account_blocked');
  return { user, payload };
}

function requireAccountType(user, expected) {
  if (user.account_type !== expected) {
    throw new HttpError(403, 'wrong_account_type');
  }
}

async function requireInternal(request, env) {
  if (request.headers.get('Origin')) throw new HttpError(403, 'forbidden');
  assertEnv(env, ['DB', 'INTERNAL_KEY']);
  const provided = request.headers.get('X-Internal-Key') || '';
  if (!timingSafeEqual(provided, env.INTERNAL_KEY)) {
    throw new HttpError(401, 'unauthorized');
  }
}

function assertId(value, code) {
  if (typeof value !== 'string' || value.length === 0 || value.length >= MAX_ID_LENGTH) {
    throw new HttpError(400, code || 'invalid_id');
  }
  return value;
}

function effectivePrice(product, now) {
  const hasOffer =
    product.offer_price_ugx != null &&
    product.offer_starts_at != null &&
    product.offer_ends_at != null &&
    now >= Number(product.offer_starts_at) &&
    now < Number(product.offer_ends_at);
  return hasOffer ? Number(product.offer_price_ugx) : Number(product.price_ugx);
}

function getBuyerFirstName(displayName) {
  if (!displayName || typeof displayName !== 'string') return 'Buyer';
  const first = displayName.trim().split(/\s+/)[0] || 'Buyer';
  return first.slice(0, 20);
}

/* ------------------------------------------------------------------ */
/* Endpoint Handlers                                                  */
/* ------------------------------------------------------------------ */

async function handleHealth(env, now, cors) {
  return json({ ok: true, service: 'earnity-referrals', time: now }, 200, cors);
}

async function handleLinksResolve(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT']);
  const dnt = request.headers.get('DNT') === '1';
  const gpc = request.headers.get('Sec-GPC') === '1';
  if (dnt || gpc) {
    return json({ valid: true, recorded: false }, 200, cors);
  }

  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  const ref = typeof body.ref === 'string' ? body.ref.trim() : '';
  if (!ref) throw new HttpError(400, 'invalid_ref');

  const refereeUser = await env.DB.prepare(
    `SELECT u.id FROM referee_usernames ru JOIN users u ON u.id = ru.user_id WHERE ru.username = ? COLLATE NOCASE LIMIT 1`
  ).bind(ref).first();
  if (!refereeUser) return json({ valid: false }, 200, cors);

  const product = await env.DB.prepare(
    `SELECT p.id FROM products p JOIN businesses b ON b.id = p.business_id WHERE p.id = ? AND p.status = 'active' AND b.approval_status = 'approved' LIMIT 1`
  ).bind(productId).first();
  if (!product) return json({ valid: false }, 200, cors);

  const slot = await env.DB.prepare(
    `SELECT id FROM product_referee_slots WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending', 'active') LIMIT 1`
  ).bind(productId, refereeUser.id).first();
  if (!slot) return json({ valid: false }, 200, cors);

  let ownerKey = '';
  const authHeader = request.headers.get('Authorization');
  if (authHeader) {
    try {
      const { user } = await requireAuth(request, env, now);
      ownerKey = 'u:' + user.id;
    } catch {}
  }
  if (!ownerKey) {
    const visitorId = request.headers.get('X-Visitor-Id');
    if (!visitorId || !VISITOR_ID_RE.test(visitorId)) {
      throw new HttpError(400, 'invalid_visitor_id');
    }
    ownerKey = 'v:' + visitorId;
  }

  await env.DB.prepare(
    `INSERT INTO referral_visits (owner_key, product_id, referee_user_id, created_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(owner_key, product_id, referee_user_id) DO UPDATE SET created_at = ?`
  ).bind(ownerKey, productId, refereeUser.id, now, now).run();

  return json({ valid: true, recorded: true }, 200, cors);
}

async function handleRefereeMine(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');

  const unameRow = await env.DB.prepare(
    'SELECT username FROM referee_usernames WHERE user_id = ? LIMIT 1'
  ).bind(user.id).first();
  const username = unameRow?.username || '';

  const slots = await env.DB.prepare(
    `SELECT s.product_id, p.name AS product_name, p.commission_bps
     FROM product_referee_slots s
     JOIN products p ON p.id = s.product_id
     WHERE s.referee_user_id = ? AND s.status IN ('pending', 'active')`
  ).bind(user.id).all();

  return json(
    {
      slots: (slots.results || []).map((r) => ({
        product_id: r.product_id,
        product_name: r.product_name,
        commission_bps: Number(r.commission_bps),
        link_params: { product_id: r.product_id, ref: username },
      })),
    },
    200,
    cors
  );
}

async function handleRequestsInbox(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');

  const rows = await env.DB.prepare(
    `SELECT r.id AS request_id, r.product_id, r.message, r.created_at,
            p.name AS product_name, p.price_ugx, p.offer_price_ugx, p.offer_starts_at, p.offer_ends_at, p.commission_bps,
            u.display_name AS buyer_name
     FROM product_referee_slots s
     JOIN products p ON p.id = s.product_id
     JOIN price_requests r ON r.product_id = p.id
     JOIN users u ON u.id = r.buyer_user_id
     WHERE s.referee_user_id = ? AND s.status IN ('pending', 'active')
       AND r.status = 'open' AND r.expires_at > ?
       AND r.buyer_user_id != ?
       AND NOT EXISTS (
         SELECT 1 FROM discounts d WHERE d.request_id = r.id AND d.referee_user_id = ?
       )
     ORDER BY r.created_at DESC
     LIMIT 50`
  ).bind(user.id, now, user.id, user.id).all();

  return json(
    {
      requests: (rows.results || []).map((r) => {
        const price = effectivePrice(r, now);
        return {
          request_id: r.request_id,
          product_id: r.product_id,
          product_name: r.product_name,
          effective_price_ugx: price,
          commission_bps: Number(r.commission_bps),
          buyer_first_name: getBuyerFirstName(r.buyer_name),
          message: r.message,
          created_at: Number(r.created_at),
        };
      }),
    },
    200,
    cors
  );
}

async function handleGrantDiscount(request, env, requestId, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');
  assertId(requestId, 'invalid_request_id');

  const body = await readJson(request);
  const discountBps = Number(body.discount_bps);
  if (!Number.isInteger(discountBps) || discountBps < 1) {
    throw new HttpError(400, 'invalid_discount_bps');
  }

  const reqRow = await env.DB.prepare(
    `SELECT r.id, r.product_id, r.buyer_user_id, r.status, r.expires_at,
            p.commission_bps, b.owner_user_id
     FROM price_requests r
     JOIN products p ON p.id = r.product_id
     JOIN businesses b ON b.id = p.business_id
     WHERE r.id = ? LIMIT 1`
  ).bind(requestId).first();

  if (!reqRow || reqRow.status !== 'open' || reqRow.expires_at <= now) {
    throw new HttpError(404, 'request_not_found');
  }
  if (reqRow.buyer_user_id === user.id) {
    throw new HttpError(400, 'self_grant_not_allowed');
  }
  if (reqRow.owner_user_id === user.id) {
    throw new HttpError(400, 'business_owner_referee');
  }
  if (discountBps > Number(reqRow.commission_bps)) {
    throw new HttpError(400, 'discount_exceeds_commission');
  }

  const slot = await env.DB.prepare(
    `SELECT id FROM product_referee_slots WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending', 'active') LIMIT 1`
  ).bind(reqRow.product_id, user.id).first();
  if (!slot) throw new HttpError(403, 'no_live_slot');

  const hourAgo = now - 3600;
  const countRow = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM discounts WHERE referee_user_id = ? AND created_at >= ?`
  ).bind(user.id, hourAgo).first();
  if (Number(countRow?.n || 0) >= 30) {
    throw new HttpError(429, 'rate_limit_exceeded');
  }

  const discountId = generateId('disc_');
  const notifId = generateId('notif_');
  const expiresAt = now + DISCOUNT_VALID_SECONDS;
  const payload = JSON.stringify({
    discount_id: discountId,
    product_id: reqRow.product_id,
    discount_bps: discountBps,
  });

  let results;
  try {
    results = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO discounts (id, request_id, product_id, buyer_user_id, referee_user_id, discount_bps, status, created_at, expires_at)
         SELECT ?, ?, ?, ?, ?, ?, 'active', ?, ?
         WHERE EXISTS (SELECT 1 FROM price_requests WHERE id = ? AND status = 'open' AND expires_at > ?)`
      ).bind(discountId, requestId, reqRow.product_id, reqRow.buyer_user_id, user.id, discountBps, now, expiresAt, requestId, now),
      env.DB.prepare(
        `INSERT INTO notifications (id, user_id, type, payload, created_at)
         SELECT ?, ?, 'discount_granted', ?, ?
         WHERE EXISTS (SELECT 1 FROM discounts WHERE id = ?)`
      ).bind(notifId, reqRow.buyer_user_id, payload, now, discountId),
    ]);
  } catch (err) {
    if (String(err?.message || '').includes('UNIQUE')) {
      throw new HttpError(409, 'discount_already_granted');
    }
    throw err;
  }

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'request_closed_or_expired');
  }

  return json(
    {
      discount: {
        id: discountId,
        request_id: requestId,
        product_id: reqRow.product_id,
        discount_bps: discountBps,
        status: 'active',
        created_at: now,
        expires_at: expiresAt,
      },
    },
    201,
    cors
  );
}

async function handleCancelDiscount(request, env, discountId, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');
  assertId(discountId, 'invalid_discount_id');

  const results = await env.DB.prepare(
    `UPDATE discounts SET status = 'cancelled'
     WHERE id = ? AND referee_user_id = ? AND status = 'active'`
  ).bind(discountId, user.id).run();

  if ((results?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(404, 'discount_not_found');
  }

  return json({ cancelled: true }, 200, cors);
}

async function handleRefereeSummary(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');

  const thirtyDaysAgo = now - 30 * 86400;

  const visits = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM referral_visits WHERE referee_user_id = ? AND created_at >= ?`
  ).bind(user.id, thirtyDaysAgo).first();

  const requestsAnswered = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM discounts WHERE referee_user_id = ?`
  ).bind(user.id).first();

  const statuses = await env.DB.prepare(
    `SELECT status, COUNT(*) AS n FROM discounts WHERE referee_user_id = ? GROUP BY status`
  ).bind(user.id).all();

  const counts = { active: 0, used: 0, expired: 0, cancelled: 0 };
  for (const r of statuses.results || []) {
    counts[r.status] = Number(r.n);
  }

  return json(
    {
      link_visits_last_30_days: Number(visits?.n || 0),
      requests_answered: Number(requestsAnswered?.n || 0),
      discounts_granted: counts,
    },
    200,
    cors
  );
}

async function handleCreateRequest(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);

  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  const message = body.message != null ? String(body.message).trim() : '';
  if (message.length > MAX_MESSAGE_LENGTH) {
    throw new HttpError(400, 'message_too_long');
  }

  const product = await env.DB.prepare(
    `SELECT p.id, b.owner_user_id, b.approval_status FROM products p JOIN businesses b ON b.id = p.business_id WHERE p.id = ? AND p.status = 'active' LIMIT 1`
  ).bind(productId).first();
  if (!product || product.approval_status !== 'approved') {
    throw new HttpError(404, 'product_not_found');
  }
  if (product.owner_user_id === user.id) {
    throw new HttpError(400, 'owner_cannot_request');
  }

  const dayAgo = now - 86400;
  const countRow = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM price_requests WHERE buyer_user_id = ? AND created_at >= ?`
  ).bind(user.id, dayAgo).first();
  if (Number(countRow?.n || 0) >= 5) {
    throw new HttpError(429, 'rate_limit_exceeded');
  }

  const requestId = generateId('req_');
  const expiresAt = now + REQUEST_VALID_SECONDS;

  try {
    await env.DB.prepare(
      `INSERT INTO price_requests (id, buyer_user_id, product_id, message, status, created_at, expires_at)
       VALUES (?, ?, ?, ?, 'open', ?, ?)`
    ).bind(requestId, user.id, productId, message, now, expiresAt).run();
  } catch (err) {
    if (String(err?.message || '').includes('UNIQUE')) {
      throw new HttpError(409, 'request_already_open');
    }
    throw err;
  }

  return json(
    {
      request: {
        id: requestId,
        product_id: productId,
        message,
        status: 'open',
        created_at: now,
        expires_at: expiresAt,
      },
    },
    201,
    cors
  );
}

async function handleBuyerRequestsMine(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);

  const rows = await env.DB.prepare(
    `SELECT r.id AS request_id, r.product_id, r.status, r.created_at, r.expires_at,
            p.name AS product_name, p.price_ugx, p.offer_price_ugx, p.offer_starts_at, p.offer_ends_at, p.commission_bps,
            d.id AS discount_id, d.discount_bps, d.status AS discount_status, d.expires_at AS discount_expires_at,
            ru.username AS referee_username
     FROM price_requests r
     JOIN products p ON p.id = r.product_id
     LEFT JOIN discounts d ON d.request_id = r.id AND d.status = 'active' AND d.expires_at > ?
     LEFT JOIN referee_usernames ru ON ru.user_id = d.referee_user_id
     WHERE r.buyer_user_id = ?
     ORDER BY r.created_at DESC`
  ).bind(now, user.id).all();

  const map = new Map();
  for (const r of rows.results || []) {
    let req = map.get(r.request_id);
    if (!req) {
      const price = effectivePrice(r, now);
      req = {
        request_id: r.request_id,
        product_id: r.product_id,
        product_name: r.product_name,
        status: r.status,
        created_at: Number(r.created_at),
        expires_at: Number(r.expires_at),
        discounts: [],
      };
      map.set(r.request_id, req);
    }
    if (r.discount_id) {
      const price = effectivePrice(r, now);
      const discountUgx = Math.floor((price * Number(r.discount_bps)) / 10000);
      req.discounts.push({
        id: r.discount_id,
        discount_bps: Number(r.discount_bps),
        discount_ugx: discountUgx,
        buyer_price_ugx: price - discountUgx,
        referee_username: r.referee_username || 'referee',
        expires_at: Number(r.discount_expires_at),
      });
    }
  }

  return json({ requests: Array.from(map.values()) }, 200, cors);
}

async function handleBuyerDiscountsMine(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);

  const rows = await env.DB.prepare(
    `SELECT d.id, d.product_id, d.discount_bps, d.expires_at,
            p.name AS product_name, p.price_ugx, p.offer_price_ugx, p.offer_starts_at, p.offer_ends_at,
            ru.username AS referee_username
     FROM discounts d
     JOIN products p ON p.id = d.product_id
     LEFT JOIN referee_usernames ru ON ru.user_id = d.referee_user_id
     WHERE d.buyer_user_id = ? AND d.status = 'active' AND d.expires_at > ?
     ORDER BY d.created_at DESC`
  ).bind(user.id, now).all();

  return json(
    {
      discounts: (rows.results || []).map((r) => {
        const price = effectivePrice(r, now);
        const discountUgx = Math.floor((price * Number(r.discount_bps)) / 10000);
        return {
          id: r.id,
          product_id: r.product_id,
          product_name: r.product_name,
          discount_bps: Number(r.discount_bps),
          discount_ugx: discountUgx,
          buyer_price_ugx: price - discountUgx,
          referee_username: r.referee_username || 'referee',
          expires_at: Number(r.expires_at),
        };
      }),
    },
    200,
    cors
  );
}

async function handleNotifications(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);

  const rows = await env.DB.prepare(
    `SELECT id, type, payload, read_at, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30`
  ).bind(user.id).all();

  return json(
    {
      notifications: (rows.results || []).map((r) => ({
        id: r.id,
        type: r.type,
        payload: JSON.parse(r.payload || '{}'),
        read_at: r.read_at != null ? Number(r.read_at) : null,
        created_at: Number(r.created_at),
      })),
    },
    200,
    cors
  );
}

async function handleNotificationsRead(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  const body = await readJson(request);
  const ids = body.ids;
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > 30) {
    throw new HttpError(400, 'invalid_ids');
  }

  for (const id of ids) {
    assertId(id, 'invalid_id');
  }

  const placeholders = ids.map(() => '?').join(',');
  await env.DB.prepare(
    `UPDATE notifications SET read_at = ? WHERE user_id = ? AND id IN (${placeholders}) AND read_at IS NULL`
  ).bind(now, user.id, ...ids).run();

  return json({ marked_read: true }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* Internal Endpoints                                                 */
/* ------------------------------------------------------------------ */

async function handleInternalAttribution(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  const buyerUserId = assertId(body.buyer_user_id, 'invalid_buyer_user_id');
  const visitorId = body.visitor_id != null ? String(body.visitor_id) : null;
  const discountId = body.discount_id != null ? String(body.discount_id) : null;

  const product = await env.DB.prepare(
    `SELECT p.*, b.owner_user_id, b.referrer_user_id, b.referrer_bps, b.approval_status
     FROM products p JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? LIMIT 1`
  ).bind(productId).first();

  if (!product || product.status !== 'active' || product.approval_status !== 'approved') {
    throw new HttpError(404, 'product_not_found');
  }

  const price = effectivePrice(product, now);
  const maxCommissionBps = Number(product.commission_bps);

  let refereeUserId = null;
  let source = null;
  let activeDiscountId = null;
  let discountBps = 0;
  let capped = false;

  if (discountId) {
    const disc = await env.DB.prepare(
      `SELECT * FROM discounts WHERE id = ? AND buyer_user_id = ? AND product_id = ? AND status = 'active' AND expires_at > ? LIMIT 1`
    ).bind(discountId, buyerUserId, productId, now).first();

    if (!disc) {
      throw new HttpError(409, 'discount_not_usable');
    }

    activeDiscountId = disc.id;
    refereeUserId = disc.referee_user_id;
    source = 'discount';
    let dbps = Number(disc.discount_bps);
    if (dbps > maxCommissionBps) {
      dbps = maxCommissionBps;
      capped = true;
    }
    discountBps = dbps;
  } else {
    const sevenDaysAgo = now - LINK_CREDIT_SECONDS;
    const ownerKeys = ['u:' + buyerUserId];
    if (visitorId && VISITOR_ID_RE.test(visitorId)) {
      ownerKeys.push('v:' + visitorId);
    }

    for (const ok of ownerKeys) {
      const visit = await env.DB.prepare(
        `SELECT referee_user_id FROM referral_visits
         WHERE owner_key = ? AND product_id = ? AND created_at >= ?
         ORDER BY created_at DESC LIMIT 1`
      ).bind(ok, productId, sevenDaysAgo).first();

      if (visit) {
        const slot = await env.DB.prepare(
          `SELECT id FROM product_referee_slots WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending', 'active') LIMIT 1`
        ).bind(productId, visit.referee_user_id).first();

        if (slot) {
          refereeUserId = visit.referee_user_id;
          source = 'link';
          break;
        }
      }
    }
  }

  let productRefereeObj = null;
  if (refereeUserId) {
    const grossUgx = Math.floor((price * maxCommissionBps) / 10000);
    const discountUgx = Math.floor((price * discountBps) / 10000);
    const netUgx = Math.max(0, grossUgx - discountUgx);
    const isSelfRef = buyerUserId === refereeUserId;

    let payableUgx = netUgx;
    let earnitySurchargeUgx = 0;
    if (isSelfRef) {
      payableUgx = Math.floor((netUgx * SELF_REFERRAL_KEEP_BPS) / 10000);
      earnitySurchargeUgx = netUgx - payableUgx;
    }

    productRefereeObj = {
      user_id: refereeUserId,
      source,
      discount_id: activeDiscountId,
      commission_bps: maxCommissionBps,
      discount_bps: discountBps,
      gross_ugx: grossUgx,
      discount_ugx: discountUgx,
      net_ugx: netUgx,
      self_referral: isSelfRef,
      payable_ugx: payableUgx,
      earnity_surcharge_ugx: earnitySurchargeUgx,
      capped,
    };
  }

  let businessReferrerObj = null;
  const bizRefId = product.referrer_user_id;
  const bizRefBps = Number(product.referrer_bps || 0);
  if (bizRefId && bizRefBps > 0) {
    const grossUgx = Math.floor((price * bizRefBps) / 10000);
    const isSelfRef = buyerUserId === bizRefId;

    let payableUgx = grossUgx;
    let earnitySurchargeUgx = 0;
    if (isSelfRef) {
      payableUgx = Math.floor((grossUgx * SELF_REFERRAL_KEEP_BPS) / 10000);
      earnitySurchargeUgx = grossUgx - payableUgx;
    }

    businessReferrerObj = {
      user_id: bizRefId,
      bps: bizRefBps,
      gross_ugx: grossUgx,
      self_referral: isSelfRef,
      payable_ugx: payableUgx,
      earnity_surcharge_ugx: earnitySurchargeUgx,
    };
  }

  const finalDiscountUgx = Math.floor((price * discountBps) / 10000);
  const buyerPriceUgx = price - finalDiscountUgx;

  let discountReturn = null;
  if (activeDiscountId) {
    discountReturn = {
      id: activeDiscountId,
      discount_bps: discountBps,
      discount_ugx: finalDiscountUgx,
      buyer_price_ugx: buyerPriceUgx,
    };
  }

  return json(
    {
      product_id: productId,
      effective_price_ugx: price,
      buyer_user_id: buyerUserId,
      product_referee: productRefereeObj,
      business_referrer: businessReferrerObj,
      discount: discountReturn,
    },
    200,
    {}
  );
}

async function handleInternalDiscountConsume(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const discountId = assertId(body.discount_id, 'invalid_discount_id');
  const buyerUserId = assertId(body.buyer_user_id, 'invalid_buyer_user_id');
  const orderRef = assertId(body.order_ref, 'invalid_order_ref');

  const disc = await env.DB.prepare(
    `SELECT status, used_ref FROM discounts WHERE id = ? AND buyer_user_id = ? LIMIT 1`
  ).bind(discountId, buyerUserId).first();

  if (!disc) throw new HttpError(404, 'discount_not_found');

  if (disc.status === 'used') {
    if (disc.used_ref === orderRef) {
      return json({ consumed: true, duplicate: true }, 200, {});
    }
    throw new HttpError(409, 'discount_already_used');
  }

  if (disc.status !== 'active') {
    throw new HttpError(409, 'discount_not_active');
  }

  const results = await env.DB.prepare(
    `UPDATE discounts SET status = 'used', used_ref = ?
     WHERE id = ? AND buyer_user_id = ? AND status = 'active'`
  ).bind(orderRef, discountId, buyerUserId).run();

  if ((results?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'discount_consume_failed');
  }

  return json({ consumed: true, duplicate: false }, 200, {});
}

async function handleInternalExpire(request, env, now) {
  await requireInternal(request, env);

  const reqResult = await env.DB.prepare(
    `UPDATE price_requests SET status = 'expired' WHERE status = 'open' AND expires_at <= ?`
  ).bind(now).run();

  const discResult = await env.DB.prepare(
    `UPDATE discounts SET status = 'expired' WHERE status = 'active' AND expires_at <= ?`
  ).bind(now).run();

  const thirtyDaysAgo = now - 30 * 86400;
  let deletedVisits = 0;
  while (true) {
    const del = await env.DB.prepare(
      `DELETE FROM referral_visits WHERE created_at < ? AND rowid IN (SELECT rowid FROM referral_visits WHERE created_at < ? LIMIT 5000)`
    ).bind(thirtyDaysAgo, thirtyDaysAgo).run();
    const changes = del?.meta?.changes || 0;
    deletedVisits += changes;
    if (changes < 5000) break;
  }

  return json(
    {
      expired_requests: reqResult?.meta?.changes || 0,
      expired_discounts: discResult?.meta?.changes || 0,
      deleted_visits: deletedVisits,
    },
    200,
    {}
  );
}

/* ------------------------------------------------------------------ */
/* Worker Entrypoint                                                  */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const now = Math.floor(Date.now() / 1000);
    const origin = request.headers.get('Origin');

    if (origin && !isAllowedOrigin(origin)) {
      return json({ error: 'origin_not_allowed' }, 403, {});
    }

    const cors = corsHeaders(origin);
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/internal/') && origin) {
      return json({ error: 'forbidden' }, 403, {});
    }

    if (request.method === 'OPTIONS') {
      if (path.startsWith('/internal/')) {
        return json({ error: 'forbidden' }, 403, {});
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    try {
      if (path === '/health' && request.method === 'GET') {
        return await handleHealth(env, now, cors);
      }
      if (path === '/links/resolve' && request.method === 'POST') {
        return await handleLinksResolve(request, env, now, cors);
      }
      if (path === '/links/mine' && request.method === 'GET') {
        return await handleRefereeMine(request, env, now, cors);
      }
      if (path === '/requests/inbox' && request.method === 'GET') {
        return await handleRequestsInbox(request, env, now, cors);
      }
      const grantMatch = path.match(/^\/requests\/([^/]+)\/grant$/);
      if (grantMatch && request.method === 'POST') {
        return await handleGrantDiscount(request, env, grantMatch[1], now, cors);
      }
      const cancelMatch = path.match(/^\/discounts\/([^/]+)\/cancel$/);
      if (cancelMatch && request.method === 'POST') {
        return await handleCancelDiscount(request, env, cancelMatch[1], now, cors);
      }
      if (path === '/referee/summary' && request.method === 'GET') {
        return await handleRefereeSummary(request, env, now, cors);
      }
      if (path === '/requests' && request.method === 'POST') {
        return await handleCreateRequest(request, env, now, cors);
      }
      if (path === '/requests/mine' && request.method === 'GET') {
        return await handleBuyerRequestsMine(request, env, now, cors);
      }
      if (path === '/discounts/mine' && request.method === 'GET') {
        return await handleBuyerDiscountsMine(request, env, now, cors);
      }
      if (path === '/notifications' && request.method === 'GET') {
        return await handleNotifications(request, env, now, cors);
      }
      if (path === '/notifications/read' && request.method === 'POST') {
        return await handleNotificationsRead(request, env, now, cors);
      }

      /* Internal */
      if (path === '/internal/attribution' && request.method === 'POST') {
        return await handleInternalAttribution(request, env, now);
      }
      if (path === '/internal/discount-consume' && request.method === 'POST') {
        return await handleInternalDiscountConsume(request, env, now);
      }
      if (path === '/internal/expire' && request.method === 'POST') {
        return await handleInternalExpire(request, env, now);
      }

      return json({ error: 'not_found' }, 404, cors);
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.code, ...(err.extra || {}) }, err.status, cors);
      }
      console.error('unhandled_error', { name: err?.name, message: err?.message });
      return json({ error: 'server_error' }, 500, cors);
    }
  },
};
