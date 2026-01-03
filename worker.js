// worker.js - extended: /register, /login, keeps /bot-login
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/register" && request.method === "POST") return handleRegister(request, env);
    if (url.pathname === "/login" && request.method === "POST") return handleLogin(request, env);
    if (url.pathname === "/bot-login" && request.method === "POST") return botLogin(request, env);
    return json({ error: "Not Found" }, 404);
  }
};

function corsHeaders() {
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders() });
}

async function sha256Hex(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  const arr = Array.from(new Uint8Array(buf));
  return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

/* produce a compact base64url string */
function base64url(bytes) {
  const b64 = typeof bytes === "string"
    ? btoa(bytes)
    : btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function signToken(payloadObj, env, ttlSeconds = 3600) {
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET not set");
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = Object.assign({}, payloadObj, { iat: now, exp: now + ttlSeconds });
  const headerB = base64url(JSON.stringify(header));
  const payloadB = base64url(JSON.stringify(payload));
  const data = `${headerB}.${payloadB}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigB = base64url(new Uint8Array(sig));
  return `${data}.${sigB}`;
}

/* ---------------------------------------
   POST /register
   body: { username, salt, hash }
   -> posts to REGISTRATION_WEBHOOK_URL
   --------------------------------------- */
async function handleRegister(request, env) {
  try {
    if (!env.REGISTRATION_WEBHOOK_URL) return json({ error: "Server not configured (REGISTRATION_WEBHOOK_URL)" }, 500);
    const j = await request.json();
    const username = (j.username || "").toString().trim();
    const salt = (j.salt || "").toString().trim();
    const hash = (j.hash || "").toString().trim();
    if (!username || !salt || !hash) return json({ error: "username,salt,hash required" }, 400);

    // Build registration message (simple canonical format)
    const content = `REGISTER: ${username}|${salt}|${hash}|${new Date().toISOString()}`;

    // Send to Discord webhook (server-side)
    // Use JSON payload; Discord webhook accepts { content: "..." }
    const res = await fetch(env.REGISTRATION_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      return json({ ok: false, reason: "webhook post failed", status: res.status, detail: txt }, 502);
    }

    return json({ ok: true });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

/* ---------------------------------------
   POST /login
   body: { username, password }
   -> Worker reads recent messages from registration channel using bot token,
      finds latest REGISTER: username|salt|hash, recomputes sha and compares.
   -> returns { ok:true, token } on success
   --------------------------------------- */
async function handleLogin(request, env) {
  try {
    if (!env.BOT_TOKEN || !env.REGISTRATION_CHANNEL_ID) {
      return json({ error: "Server not configured (BOT_TOKEN or REGISTRATION_CHANNEL_ID)" }, 500);
    }
    const j = await request.json();
    const username = (j.username || "").toString().trim();
    const password = (j.password || "").toString();
    if (!username || !password) return json({ error: "username & password required" }, 400);

    // Fetch recent messages from the registration channel
    const discordUrl = `https://discord.com/api/v10/channels/${env.REGISTRATION_CHANNEL_ID}/messages?limit=100`;
    const res = await fetch(discordUrl, {
      headers: { Authorization: `Bot ${env.BOT_TOKEN}`, "User-Agent": "PurpleBoardAuth/1.0" }
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      return json({ ok: false, reason: "discord fetch failed", status: res.status, detail: txt }, 502);
    }
    const messages = await res.json();

    // find most recent REGISTER: entry for username (messages are reverse-chronological)
    let found = null;
    for (const m of messages) {
      if (!m.content) continue;
      if (!m.content.startsWith("REGISTER:")) continue;
      const parts = m.content.slice("REGISTER:".length).trim();
      const seg = parts.split("|");
      if (seg.length < 3) continue;
      const regUser = seg[0].trim();
      const regSalt = seg[1].trim();
      const regHash = seg[2].trim();
      if (regUser === username) { found = { salt: regSalt, hash: regHash, msgId: m.id, ts: m.timestamp }; break; }
    }

    if (!found) return json({ ok: false, reason: "no_registration" }, 404);

    const computed = await sha256Hex(found.salt + "|" + password);
    if (computed !== found.hash) return json({ ok: false, reason: "invalid_password" }, 401);

    // success: sign a session token (requires SESSION_SECRET env var)
    const token = await signToken({ username }, env, 60 * 60); // 1 hour
    return json({ ok: true, token });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

/* ---------------------------------------
   keep your existing botLogin behavior (verifies guild membership)
   This function is mostly unchanged from your uploaded worker.js
   --------------------------------------- */
async function botLogin(request, env) {
  try {
    const { user_id } = await request.json();
    if (!user_id) return json({ error: "user_id required" }, 400);
    if (!env.BOT_TOKEN || !env.GUILD_ID) return json({ error: "Server not configured" }, 500);

    const apiUrl = `https://discord.com/api/v10/guilds/${env.GUILD_ID}/members/${user_id}`;
    const res = await fetch(apiUrl, {
      headers: {
        Authorization: `Bot ${env.BOT_TOKEN}`,
        "User-Agent": "PurpleBoardAuth/1.0"
      }
    });

    if (res.status === 404) return json({ ok: false, reason: "not_a_member" }, 404);
    if (!res.ok) {
      const text = await res.text();
      return json({ ok: false, status: res.status, detail: text }, 502);
    }

    const member = await res.json();
    return json({
      ok: true,
      id: member.user.id,
      username: member.user.username,
      discriminator: member.user.discriminator,
      avatar: member.user.avatar,
      nick: member.nick || null,
      roles: member.roles || []
    });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}
