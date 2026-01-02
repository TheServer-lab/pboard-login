// Discord bot-based login verification (Cloudflare Worker)
// Uses Bot token stored as a Worker secret (BOT_TOKEN)
// Verifies whether a user ID is a member of a guild

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/bot-login" && request.method === "POST") {
      return botLogin(request, env);
    }

    return new Response("Not Found", { status: 404 });
  }
};

async function botLogin(request, env) {
  try {
    const { user_id } = await request.json();

    if (!user_id) {
      return json({ error: "user_id required" }, 400);
    }

    if (!env.BOT_TOKEN || !env.GUILD_ID) {
      return json({ error: "Server not configured" }, 500);
    }

    const apiUrl = `https://discord.com/api/v10/guilds/${env.GUILD_ID}/members/${user_id}`;

    const res = await fetch(apiUrl, {
      headers: {
        Authorization: `Bot ${env.BOT_TOKEN}`,
        "User-Agent": "PurpleBoardAuth/1.0"
      }
    });

    if (res.status === 404) {
      return json({ ok: false, reason: "not_a_member" }, 404);
    }

    if (!res.ok) {
      const text = await res.text();
      return json({ ok: false, status: res.status, detail: text }, 502);
    }

    const member = await res.json();

    // Return ONLY safe public info
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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
