require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const path = require("path");

const { getClient } = require("./oidc");
const { insertEvent, initIfNeeded, purgeOldEvents, listLatestEvents } = require("./db");
const { authorizeGuest } = require("./unifi");

const app = express();

// Derrière Nginx reverse-proxy
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "change-me"));

const PORT = parseInt(process.env.PORT || "3000", 10);
const BASE_URL = process.env.BASE_URL;
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || "180", 10);
const CONSENT_VERSION = process.env.CONSENT_VERSION || "1.0";
const DEFAULT_MINUTES = parseInt(process.env.DEFAULT_MINUTES || "480", 10);

// True en prod (HTTPS). Pour debug en HTTP direct: SECURE_COOKIES=false
const SECURE_COOKIES = (process.env.SECURE_COOKIES || "true").toLowerCase() === "true";

// --------------------
// Cookie helpers
// --------------------
function setPending(res, obj) {
  res.cookie("pending", JSON.stringify(obj), {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE_COOKIES,
    maxAge: 10 * 60 * 1000, // 10 min
  });
}
function getPending(req) {
  const raw = req.signedCookies?.pending;
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
function clearPending(res) {
  res.clearCookie("pending");
}

function render(template, vars = {}) {
  let s = template;
  for (const [k, v] of Object.entries(vars)) {
    s = s.replaceAll(`{{${k}}}`, String(v));
  }
  return s;
}

// Templates
const tplIndex = fs.readFileSync(path.join(__dirname, "views", "index.html"), "utf8");
const tplOk = fs.readFileSync(path.join(__dirname, "views", "ok.html"), "utf8");
const tplErr = fs.readFileSync(path.join(__dirname, "views", "error.html"), "utf8");

// --------------------
// Admin Basic Auth (Option B)
// --------------------
function basicAuth(req, res, next) {
  const user = process.env.ADMIN_USER || "";
  const pass = process.env.ADMIN_PASS || "";

  if (!user || !pass) {
    // Sécurité : si pas configuré, on bloque
    return res.status(503).send("Admin non configuré (ADMIN_USER/ADMIN_PASS manquants).");
  }

  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="WiFi Admin"');
    return res.status(401).send("Auth required");
  }

  const decoded = Buffer.from(hdr.slice(6), "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const u = idx >= 0 ? decoded.slice(0, idx) : "";
  const p = idx >= 0 ? decoded.slice(idx + 1) : "";

  if (u !== user || p !== pass) {
    res.setHeader("WWW-Authenticate", 'Basic realm="WiFi Admin"');
    return res.status(401).send("Invalid credentials");
  }

  next();
}

// --------------------
// UniFi captive paths → redirect vers "/"
// --------------------
function redirectToRootWithQuery(req, res) {
  const qs = new URLSearchParams(req.query).toString();
  res.redirect(qs ? `/?${qs}` : "/");
}
app.get(/^\/guests\/s\/.+/i, redirectToRootWithQuery);
app.get(/^\/guest\/s\/.+/i, redirectToRootWithQuery);

// Certains CNA arrivent en GET /start (au lieu de POST) → renvoie à l’accueil
app.get("/start", (req, res) => res.redirect("/"));

// --------------------
// Landing
// --------------------
app.get("/", async (req, res) => {
  // UniFi fournit souvent la MAC client via "id"
  const pending = {
    mac: (req.query.mac || req.query.client_mac || req.query.id || "").toString(),
    ap: (req.query.ap || req.query.ap_mac || "").toString(),
    ssid: (req.query.ssid || "").toString(),
    q: Object.fromEntries(Object.entries(req.query).slice(0, 30)),
  };

  setPending(res, pending);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(render(tplIndex, { RETENTION_DAYS }));
});

// --------------------
// Start OIDC
// --------------------
app.post("/start", async (req, res) => {
  try {
    const consent = req.body.consent === "yes";
    if (!consent) {
      res.status(400).send(render(tplErr, { MSG: "Consentement requis." }));
      return;
    }

    const pending = getPending(req);
    if (!pending?.mac) {
      res.status(400).send(render(tplErr, { MSG: "Paramètres captive manquants (MAC)." }));
      return;
    }

    pending.consented_at = new Date().toISOString();
    setPending(res, pending);

    const { oidc, config, redirectUri } = await getClient();

    const state = uuidv4();
    res.cookie("oidc_state", state, {
      signed: true,
      httpOnly: true,
      sameSite: "lax",
      secure: SECURE_COOKIES,
      maxAge: 10 * 60 * 1000,
    });

    const authUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: "openid email",
      state,
      prompt: "select_account",
    });

    res.redirect(authUrl.toString());
  } catch (e) {
    console.error("ERROR in /start:", e?.message || e);
    res.status(500).send(render(tplErr, { MSG: "Erreur interne pendant le démarrage de l'authentification." }));
  }
});

// --------------------
// OIDC callback
// --------------------
app.get("/auth/google/callback", async (req, res) => {
  const event_id = uuidv4();
  const userAgent = req.get("user-agent") || null;

  const forwardedFor = req.headers["x-forwarded-for"]?.toString();
  const clientIp = forwardedFor?.split(",")[0]?.trim() || req.socket.remoteAddress || null;

  const pending = getPending(req);
  const expectedState = req.signedCookies?.oidc_state;

  const baseEvent = {
    event_id,
    result: "FAIL",
    failure_reason: null,
    oidc_issuer: null,
    oidc_sub: null,
    email: null,
    client_mac: pending?.mac || null,
    ap_mac: pending?.ap || null,
    ssid: pending?.ssid || null,
    client_ip: clientIp,
    user_agent: userAgent,
    consent_version: CONSENT_VERSION,
    consented_at: pending?.consented_at ? new Date(pending.consented_at) : null,
    retention_days: RETENTION_DAYS,
    duration_granted_minutes: DEFAULT_MINUTES,
  };

  try {
    if (!pending?.mac) throw new Error("MAC manquante (pending cookie).");
    if (!expectedState) throw new Error("State manquant (cookie).");
    if (req.query.state !== expectedState) throw new Error("State invalide.");

    const { oidc, config, redirectUri } = await getClient();

    const callbackUrl = new URL(`${BASE_URL}${req.originalUrl}`);

    const tokenSet = await oidc.authorizationCodeGrant(config, callbackUrl, {
      redirect_uri: redirectUri,
      expectedState,
    });

    const idToken = tokenSet?.id_token;
    const accessToken = tokenSet?.access_token;

    if (!idToken) throw new Error("id_token absent du retour OIDC.");

    // Decode JWT payload (debug) pour obtenir sub et éventuellement email
    const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
    const sub = payload.sub || null;
    const iss = payload.iss || "https://accounts.google.com";
    let email = payload.email || null;

    // UserInfo (openid-client v6 exige expectedSubject=sub)
    if (accessToken && sub && typeof oidc.fetchUserInfo === "function") {
      const ui = await oidc.fetchUserInfo(config, accessToken, sub);
      email = ui?.email || email;
    }

    baseEvent.oidc_issuer = iss;
    baseEvent.oidc_sub = sub;
    baseEvent.email = email;

    // Autorise le client dans UniFi
    await authorizeGuest(pending.mac, DEFAULT_MINUTES);

    baseEvent.result = "SUCCESS";
    await insertEvent(baseEvent);

    clearPending(res);
    res.clearCookie("oidc_state");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(tplOk);
  } catch (e) {
    baseEvent.failure_reason = (e && e.message) ? e.message.slice(0, 200) : "unknown";
    try {
      await insertEvent(baseEvent);
    } catch {}
    console.error("ERROR in callback:", e?.message || e);
    res.status(400).send(render(tplErr, { MSG: baseEvent.failure_reason }));
  }
});

// --------------------
// Admin page
// --------------------
app.get("/admin", basicAuth, async (req, res) => {
  // filtres simples via query string
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);
  const q = (req.query.q || "").toString().trim(); // email ou MAC (contient)
  const result = (req.query.result || "").toString().trim(); // SUCCESS/FAIL

  const rows = await listLatestEvents({ limit, q, result });

  const escape = (s) =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");

  const trs = rows
    .map(
      (r) => `
    <tr>
      <td>${escape(r.created_at)}</td>
      <td>${escape(r.result)}</td>
      <td>${escape(r.email)}</td>
      <td>${escape(r.client_mac)}</td>
      <td>${escape(r.ssid)}</td>
      <td>${escape(r.ap_mac)}</td>
      <td>${escape(r.client_ip)}</td>
      <td>${escape(r.failure_reason)}</td>
    </tr>`
    )
    .join("");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Admin WiFi - Logs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; }
    h1 { margin: 0 0 8px 0; }
    .muted { color: #666; font-size: 14px; margin: 0 0 16px 0; }
    form { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin: 10px 0 16px 0; }
    input, select { padding: 8px; }
    table { border-collapse: collapse; width: 100%; font-size: 14px; }
    th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: #fff; }
    code { background:#f4f4f4; padding:2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Logs connexions WiFi</h1>
  <p class="muted">
    Derniers ${rows.length} événements. Filtre via <code>?q=email|mac</code>, <code>?result=SUCCESS|FAIL</code>, <code>?limit=200</code>
  </p>

  <form method="GET" action="/admin">
    <input name="q" value="${escape(q)}" placeholder="email ou MAC (contient)" />
    <select name="result">
      <option value="" ${result === "" ? "selected" : ""}>Tous</option>
      <option value="SUCCESS" ${result === "SUCCESS" ? "selected" : ""}>SUCCESS</option>
      <option value="FAIL" ${result === "FAIL" ? "selected" : ""}>FAIL</option>
    </select>
    <input name="limit" value="${escape(limit)}" style="width:90px" />
    <button type="submit">Filtrer</button>
  </form>

  <table>
    <thead>
      <tr>
        <th>Date</th><th>Résultat</th><th>Email</th><th>MAC</th><th>SSID</th><th>AP</th><th>IP</th><th>Erreur</th>
      </tr>
    </thead>
    <tbody>${trs}</tbody>
  </table>
</body>
</html>`);
});

// (optionnel) JSON pour debug / intégration
app.get("/admin/logs.json", basicAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);
  const q = (req.query.q || "").toString().trim();
  const result = (req.query.result || "").toString().trim();
  const rows = await listLatestEvents({ limit, q, result });
  res.json({ count: rows.length, rows });
});

// Healthcheck
app.get("/healthz", (req, res) => res.json({ ok: true }));

// 404 helper
app.use((req, res) => {
  res.status(404).send(`Not Found: ${req.method} ${req.path}`);
});

async function main() {
  if (!BASE_URL) {
    console.error("BASE_URL missing (e.g. https://gab-wifi.duckdns.org)");
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL missing");
    process.exit(1);
  }
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) {
    console.error("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI");
    process.exit(1);
  }

  await initIfNeeded();

  setInterval(() => {
    purgeOldEvents().catch(() => {});
  }, 24 * 60 * 60 * 1000);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Portal listening on :${PORT}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
