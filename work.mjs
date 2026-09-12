/*
 * KeyServer Cloudflare Worker - compatible with liberroiapi_newapi.so
 * Required KV binding: KEYS
 */

const DAY = 86400;
const SESSION_TTL = 3600;
const MAX_BODY = 32768;
const PACKAGE_ID = "pkg_f2d0267930315f093b0fdaef";
const AES_KEY_HEX = "8397afc669388137586c053273ea26adcf9dd26f01330865c2e3a8df614c33ec";
const LEGACY_SALT = "Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E";
const enc = new TextEncoder();
const dec = new TextDecoder();

class InputError extends Error {}

const now = () => Math.floor(Date.now() / 1000);
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const botToken = (env) => env.TELEGRAM_BOT_TOKEN_SECURE || env.TELEGRAM_BOT_TOKEN;
const packageId = (env) => String(env.PACKAGE_ID || PACKAGE_ID);
const aesKeyHex = (env) => String(env.AES_KEY_HEX || AES_KEY_HEX).trim().toLowerCase();

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Signature",
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...CORS,
    },
  });
}

function html(value) {
  return String(value ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}

function expiry(value) {
  return value === 0
    ? "Vinh vien"
    : new Date(value * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

function randomHex(byteLength) {
  return [...crypto.getRandomValues(new Uint8Array(byteLength))]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(value) {
  if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error("AES_KEY_HEX must contain 64 hex characters");
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

function base64ToBytes(value) {
  if (typeof value !== "string" || value.length < 4 || value.length > MAX_BODY * 2) {
    throw new InputError("Invalid encrypted data");
  }
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    throw new InputError("Invalid encrypted data");
  }
}

function bytesToBase64(value) {
  let binary = "";
  for (let offset = 0; offset < value.length; offset += 8192) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

async function importAesKey(env) {
  return crypto.subtle.importKey("raw", hexToBytes(aesKeyHex(env)), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// Native format: base64(12-byte IV || 16-byte GCM tag || ciphertext).
async function decryptNative(data, env) {
  const packed = base64ToBytes(data);
  if (packed.length <= 28) throw new InputError("Invalid encrypted data");
  const iv = packed.slice(0, 12);
  const tag = packed.slice(12, 28);
  const ciphertext = packed.slice(28);
  const webCryptoInput = new Uint8Array(ciphertext.length + tag.length);
  webCryptoInput.set(ciphertext, 0);
  webCryptoInput.set(tag, ciphertext.length);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      await importAesKey(env),
      webCryptoInput,
    );
    const parsed = JSON.parse(dec.decode(plaintext));
    if (!isObject(parsed)) throw new Error("Object required");
    return parsed;
  } catch {
    throw new InputError("Encrypted payload verification failed");
  }
}

async function encryptNative(payload, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    await importAesKey(env),
    enc.encode(JSON.stringify(payload)),
  ));
  const ciphertext = encrypted.slice(0, -16);
  const tag = encrypted.slice(-16);
  const packed = new Uint8Array(iv.length + tag.length + ciphertext.length);
  packed.set(iv, 0);
  packed.set(tag, 12);
  packed.set(ciphertext, 28);
  return bytesToBase64(packed);
}

async function nativeEnvelope(payload, env) {
  return {
    data: await encryptNative(payload, env),
    sig: "00".repeat(64),
    mac: "00".repeat(32),
    ts: now(),
  };
}

async function readBody(req) {
  const buffer = new Uint8Array(await req.arrayBuffer());
  if (buffer.length === 0 || buffer.length > MAX_BODY) throw new InputError("Invalid request body");
  const text = dec.decode(buffer);
  const type = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  try {
    let result;
    if (type === "application/x-www-form-urlencoded") {
      const params = new URLSearchParams(text);
      if (new Set(params.keys()).size !== [...params].length) throw new Error("Duplicate fields");
      result = Object.fromEntries(params);
    } else {
      result = JSON.parse(text);
    }
    if (!isObject(result)) throw new Error("Object required");
    return result;
  } catch {
    throw new InputError("Invalid request body");
  }
}

function stringField(body, names, required = true, maxBytes = 256) {
  const values = names.filter((name) => has(body, name)).map((name) => body[name]);
  if (values.some((value) => typeof value !== "string")) throw new InputError(`Invalid ${names[0]}`);
  const trimmed = values.map((value) => value.trim());
  if (new Set(trimmed).size > 1) throw new InputError(`Conflicting ${names[0]}`);
  const value = trimmed[0] || "";
  if (required && !value) throw new InputError(`Missing ${names[0]}`);
  if (enc.encode(value).length > maxBytes || /[\x00-\x1f\x7f]/.test(value)) throw new InputError(`Invalid ${names[0]}`);
  return value;
}

function validateNativeMetadata(body, outer, env) {
  const suppliedPackage = String(outer.package_id || body.package_id || "");
  if (suppliedPackage && suppliedPackage !== packageId(env)) throw new InputError("Invalid package_id");
  const timestamp = Number(body.timestamp || body.ts || 0);
  if (timestamp && (!Number.isSafeInteger(timestamp) || Math.abs(now() - timestamp) > 300)) {
    throw new InputError("Request timestamp drift too large");
  }
}

async function decodeRequest(req, env) {
  const outer = await readBody(req);
  const encrypted = typeof outer.data === "string" && (has(outer, "package_id") || req.headers.has("X-Signature"));
  if (!encrypted) return { encrypted: false, outer, body: outer };
  if (String(outer.package_id || "") !== packageId(env)) throw new InputError("Invalid package_id");
  const body = await decryptNative(outer.data, env);
  validateNativeMetadata(body, outer, env);
  return { encrypted: true, outer, body };
}

async function getKey(env, key) {
  const raw = await env.KEYS.get(`key:${key}`);
  if (raw === null) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

const putKey = (env, key, meta) => env.KEYS.put(`key:${key}`, JSON.stringify(meta));

function validMeta(meta) {
  return isObject(meta)
    && typeof meta.active === "boolean"
    && Number.isSafeInteger(meta.expires_at)
    && meta.expires_at >= 0
    && meta.expires_at <= 8640000000000
    && typeof meta.hwid === "string";
}

function keyState(meta, hwid) {
  if (!meta || !validMeta(meta) || !meta.active) return "Key not found or disabled";
  if (meta.expires_at !== 0 && now() >= meta.expires_at) return "Key expired";
  if (meta.hwid && meta.hwid !== hwid) return "Device mismatch";
  return "";
}

function loginPayload(meta, key, hwid, seller, session, ttl) {
  return {
    status: "ok",
    message: "Xac thuc thanh cong",
    key,
    plan: String(meta.plan || "VIP"),
    expiresAt: String(meta.expires_at),
    session,
    session_ttl: ttl,
    EXP: expiry(meta.expires_at),
    seller,
    data: {
      EXP: expiry(meta.expires_at),
      seller,
      token: md5(`FFROOT-${key}-${hwid}-${LEGACY_SALT}`),
    },
  };
}

async function createSession(env, key, hwid, meta) {
  const session = randomHex(32);
  const remaining = meta.expires_at === 0 ? SESSION_TTL : Math.max(1, meta.expires_at - now());
  const ttl = Math.min(SESSION_TTL, remaining);
  const record = { key, hwid, expires_at: now() + ttl };
  await env.KEYS.put(`session:${session}`, JSON.stringify(record), { expirationTtl: Math.max(60, ttl) });
  return { session, ttl };
}

async function login(req, env, path) {
  const decoded = await decodeRequest(req, env);
  const body = decoded.body;
  const key = stringField(body, decoded.encrypted ? ["key"] : ["user_key", "key"]);
  const hwid = stringField(body, ["hwid", "serial"]);
  const nativeLegacy = !decoded.encrypted && (path === "/" || path === "/ca.php" || has(body, "user_key"));
  if (nativeLegacy && stringField(body, ["game"]) !== "FFROOT") {
    return json({ status: false, reason: "Unsupported game", message: "Unsupported game" });
  }
  const meta = await getKey(env, key);
  const reason = keyState(meta, hwid);
  if (reason) {
    const payload = { status: "error", reason, message: reason };
    return decoded.encrypted ? json(await nativeEnvelope(payload, env)) : json(payload);
  }
  if (!meta.hwid) {
    meta.hwid = hwid;
    await putKey(env, key, meta);
  }
  await env.KEYS.put(`hwid:${hwid}`, key);
  const { session, ttl } = await createSession(env, key, hwid, meta);
  const seller = String(meta.seller || env.SELLER_NAME || "ShopGame11919");
  const payload = loginPayload(meta, key, hwid, seller, session, ttl);
  if (decoded.encrypted) return json(await nativeEnvelope(payload, env));
  if (nativeLegacy) payload.status = true;
  return json(payload);
}

async function checkDevice(req, env) {
  const decoded = await decodeRequest(req, env);
  const hwid = stringField(decoded.body, ["hwid", "serial"]);
  const key = await env.KEYS.get(`hwid:${hwid}`);
  const meta = key ? await getKey(env, key) : null;
  const reason = key ? keyState(meta, hwid) : "Device not registered";
  let payload;
  if (reason) {
    if (key) await env.KEYS.delete(`hwid:${hwid}`);
    payload = {
      status: "ok",
      registered: false,
      message: reason,
      session: "",
      session_ttl: 0,
      keys: [],
    };
  } else {
    const { session, ttl } = await createSession(env, key, hwid, meta);
    payload = {
      status: "ok",
      registered: true,
      message: "Device registered",
      session,
      session_ttl: ttl,
      keys: [{
        key,
        plan: String(meta.plan || "VIP"),
        status: "active",
        expiresAt: String(meta.expires_at),
      }],
    };
  }
  return decoded.encrypted ? json(await nativeEnvelope(payload, env)) : json(payload);
}

async function heartbeat(req, env) {
  const decoded = await decodeRequest(req, env);
  const session = stringField(decoded.body, ["session"]);
  const hwid = stringField(decoded.body, ["hwid", "serial"]);
  const raw = await env.KEYS.get(`session:${session}`);
  let record = null;
  try { record = raw ? JSON.parse(raw) : null; } catch { record = null; }
  let reason = "";
  if (!isObject(record) || record.hwid !== hwid || !Number.isSafeInteger(record.expires_at) || now() >= record.expires_at) {
    reason = "Session expired";
  }
  const meta = reason ? null : await getKey(env, record.key);
  if (!reason) reason = keyState(meta, hwid);
  let payload;
  if (reason) {
    await env.KEYS.delete(`session:${session}`);
    payload = { status: "error", reason, message: reason, session_ttl: 0 };
  } else {
    const remaining = meta.expires_at === 0 ? SESSION_TTL : Math.max(1, meta.expires_at - now());
    const ttl = Math.min(SESSION_TTL, remaining);
    record.expires_at = now() + ttl;
    await env.KEYS.put(`session:${session}`, JSON.stringify(record), { expirationTtl: Math.max(60, ttl) });
    payload = {
      status: "ok",
      message: "heartbeat ok",
      session,
      session_ttl: ttl,
      expiresAt: String(meta.expires_at),
      plan: String(meta.plan || "VIP"),
    };
  }
  return decoded.encrypted ? json(await nativeEnvelope(payload, env)) : json(payload);
}

function md5(text) {
  const src = enc.encode(text), len = Math.ceil((src.length + 9) / 64) * 64;
  const data = new Uint8Array(len);
  data.set(src); data[src.length] = 128;
  const view = new DataView(data.buffer);
  view.setUint32(len - 8, (src.length * 8) >>> 0, true);
  view.setUint32(len - 4, Math.floor(src.length / 536870912), true);
  const shifts = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let offset = 0; offset < len; offset += 64) {
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i += 1) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const sum = (a + f + Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) + view.getUint32(offset + 4 * g, true)) | 0;
      const shift = shifts[4 * Math.floor(i / 16) + (i % 4)];
      [a, b, c, d] = [d, (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0, b, c];
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  return [a0, b0, c0, d0]
    .flatMap((value) => [0, 8, 16, 24].map((shift) => ((value >>> shift) & 255).toString(16).padStart(2, "0")))
    .join("");
}

async function tgSend(env, chatId, text) {
  const response = await fetch(`https://api.telegram.org/bot${botToken(env)}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: "HTML" }),
  });
  if (!response.ok || !(await response.json()).ok) throw new Error("Telegram send failed");
}

function describe(key, meta) {
  return `${meta.active ? "🟢" : "🔴"} <code>${html(key)}</code>\nplan: ${html(meta.plan)} | han: ${html(expiry(meta.expires_at))}\nhwid: ${html(meta.hwid || "chua bind")} | note: ${html(String(meta.note || "-").slice(0, 256))}`;
}

function daysOf(value) {
  if (!/^\d+$/.test(value)) throw new InputError("So ngay phai trong 1..36500.");
  const days = Number(value);
  if (days < 1 || days > 36500) throw new InputError("So ngay phai trong 1..36500.");
  return days;
}

async function telegram(req, env) {
  if (!env.TELEGRAM_WEBHOOK_SECRET || !botToken(env) || !env.ADMIN_TELEGRAM_ID) {
    return json({ ok: false, error: "Telegram configuration missing" }, 503);
  }
  if (req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TELEGRAM_WEBHOOK_SECRET) {
    return json({ ok: false, error: "Forbidden" }, 403);
  }
  const update = await readBody(req), message = update.message;
  if (!message || String(message.from?.id) !== String(env.ADMIN_TELEGRAM_ID)) return json({ ok: true });
  if (message.chat?.type !== "private" || String(message.chat.id) !== String(message.from.id)) return json({ ok: true });
  if (typeof message.text !== "string") return json({ ok: true });
  const parts = message.text.trim().split(/\s+/);
  const command = parts[0].replace(/^\/+/, "").split("@")[0].toLowerCase();
  const send = (text) => tgSend(env, message.chat.id, text);
  try {
    if (command === "help" || command === "start") {
      await send("<b>KeyServer</b>\n/newkey 30 [note]\n/newkey perm\n/newkey vip\n/checkkey MDK-...\n/delkey MDK-...\n/extend MDK-... 30\n/unbind MDK-...\n/listkeys [cursor]");
    } else if (command === "newkey") {
      const arg = (parts[1] || "30").toLowerCase();
      const permanent = ["perm", "vip", "vinhvien", "0", "-"].includes(arg);
      const days = permanent ? 0 : daysOf(arg);
      const plan = days ? `${days} ngay` : arg === "vip" ? "VIP vinh vien" : "Vinh vien";
      const key = `MDK-${randomHex(8).toUpperCase().match(/.{4}/g).join("-")}`;
      await putKey(env, key, { active: true, hwid: "", plan, note: parts.slice(2).join(" ").slice(0, 256), created_at: now(), expires_at: days ? now() + days * DAY : 0 });
      await send(`✅ Tao key:\n<code>${key}</code>\nplan: <b>${plan}</b>`);
    } else if (command === "listkeys" || command === "list") {
      const page = await env.KEYS.list({ prefix: "key:", limit: 10, ...(parts[1] ? { cursor: parts[1] } : {}) });
      const lines = [];
      for (const item of page.keys) {
        const key = item.name.slice(4), meta = await getKey(env, key);
        if (validMeta(meta)) lines.push(describe(key, meta));
      }
      let chunk = "<b>Danh sach key (toi da 10 muc/trang)</b>";
      for (const line of lines) {
        if (chunk.length + line.length > 3500) { await send(chunk); chunk = ""; }
        chunk += `\n${line}`;
      }
      await send(chunk);
      if (!page.list_complete) await send(`Trang tiep: <code>/listkeys ${html(page.cursor)}</code>`);
    } else if (["delkey", "deletekey", "checkkey", "info", "extend", "unbind"].includes(command)) {
      const key = stringField({ key: parts[1] || "" }, ["key"]), meta = await getKey(env, key);
      if (!validMeta(meta)) { await send("Khong tim thay key hop le."); return json({ ok: true }); }
      if (command === "checkkey" || command === "info") await send(describe(key, meta));
      else if (command === "extend" && meta.expires_at === 0) await send("Key vinh vien, khong can gia han.");
      else {
        if (command === "delkey" || command === "deletekey") meta.active = false;
        if (command === "unbind") {
          if (meta.hwid) await env.KEYS.delete(`hwid:${meta.hwid}`);
          meta.hwid = "";
        }
        if (command === "extend") meta.expires_at = Math.max(meta.expires_at, now()) + daysOf(parts[2] || "30") * DAY;
        await putKey(env, key, meta);
        await send(`✅ Da cap nhat:\n${describe(key, meta)}`);
      }
    } else await send("Lenh khong ro. /help");
  } catch (error) {
    if (!(error instanceof InputError)) throw error;
    await send(html(error.message));
  }
  return json({ ok: true });
}

export default {
  async fetch(req, env) {
    const path = new URL(req.url).pathname.replace(/\/{2,}/g, "/");
    try {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
      if (req.method === "GET" && (path === "/" || path === "/health")) {
        return json({ status: "ok", server: "KeyServer-CF", version: "lib-compatible-v2", package_id: packageId(env), time: now() });
      }
      if (req.method === "POST") {
        if (!env.KEYS) throw new Error("KEYS binding missing");
        if (path === "/telegram") return telegram(req, env);
        if (["/", "/ca.php", "/login", "/api/login"].includes(path)) return login(req, env, path);
        if (["/check", "/api/check"].includes(path)) return checkDevice(req, env);
        if (["/session/heartbeat", "/api/session/heartbeat"].includes(path)) return heartbeat(req, env);
      }
      return json({ status: false, reason: "Not found", message: "Not found" }, 404);
    } catch (error) {
      const reason = error instanceof InputError ? error.message : "Server error; contact administrator";
      return json({ status: false, error: reason, reason, message: reason }, error instanceof InputError ? 400 : 503);
    }
  },
};

export { decryptNative, encryptNative, md5 };
