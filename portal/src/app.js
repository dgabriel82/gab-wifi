require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const path = require("path");

const { getClient } = require("./oidc");
const { insertEvent, initIfNeeded, purgeOldEvents } = require("./db");
const { authorizeGuest } = require("./unifi");

const app = express();

/**
 * Derrière Nginx reverse-proxy:
 * - req.secure et l'IP client deviennent corrects via X-Forwarded-Proto / X-Forwarded-For
 * - indispensable si tu utilises des cookies Secure.
 */
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

// Helpers cookies "pending"
function setPending(res, obj) {
  res.cookie("pending", JSON.stringify(obj), {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE_COOKIES,
    maxAge: 10 * 60 * 1000 // 10 min
  });
}
function getPending(req) {
  const raw = req.signedCookies?.pending;
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
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

const tplIndex = fs.readFileSync(path.join(__dirname, "views", "index.html"), "utf8");
const tplOk = fs.readFileSync(path.join(__dirname, "views", "ok.html"), "utf8");
const tplErr = fs.readFileSync(path.join(__dirname, "views", "error.html"), "utf8");

/**
 * UniFi captive portal paths
 * UniFi redirige souvent vers:
 *  - /guests/s/default/?id=...&ap=...&ssid=...
 * ou parfois /guest/s/...
 * On renvoie vers "/" en conservant la query string.
 */
function redirectToRootWithQuery(req, res) {
  const qs = new URLSearchParams(req.query).toString();
  res.redirect(qs ? `/?${qs}` : "/");
}
app.get(/^\/guests\/s\/.+/i, redirectToRootWithQuery);
app.get(/^\/guest\/s\/.+/i, redirectToRootWithQuery);

// Certains CNA arrivent en GET /start par erreur → on renvoie à l'accueil
app.get("/start", (req, res) => res.redirect("/"));

// Landing page
app.get("/", async (req, res) => {
  // UniFi fournit souvent la MAC client via "id" (très fréquent),
  // parfois via "mac" ou "client_mac"
  const pending = {
    mac: (req.query.mac || req.query.client_mac || req.query.id || "").toString(),
    ap: (req.query.ap || req.query.ap_mac || "").toString(),
    ssid: (req.query.ssid || "").toString(),
    // copie limitée de la query (debug uniquement; ne pas stocker long terme)
    q: Object.fromEntries(Object.entries(req.query).slice(0, 30))
  };

  setPending(res, pending);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(render(tplIndex, { RETENTION_DAYS }));
});

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

    // openid-client v6 (API "Configuration + fonctions")
    const { oidc, config, redirectUri } = await getClient();

    const state = uuidv4();
    res.cookie("oidc_state", state, {
      signed: true,
      httpOnly: true,
      sameSite: "lax",
      secure: SECURE_COOKIES,
      maxAge: 10 * 60 * 1000
    });

    const authUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: "openid email",
      state,
      prompt: "select_account"
    });

    res.redirect(authUrl.toString());
  } catch (e) {
    console.error("ERROR in /start:", e);
    res.status(500).send(render(tplErr, { MSG: "Erreur interne pendant le démarrage de l'authentification." }));
  }
});

app.get("/auth/google/callback", async (req, res) => {
  const event_id = uuidv4();
  const userAgent = req.get("user-agent") || null;

  const forwardedFor = req.headers["x-forwarded-for"]?.toString();
  const clientIp =
    forwardedFor?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    null;

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
    duration_granted_minutes: DEFAULT_MINUTES
  };

  try {
    if (!pending?.mac) throw new Error("MAC manquante (pending cookie).");
    if (!expectedState) throw new Error("State manquant (cookie).");
    if (req.query.state !== expectedState) throw new Error("State invalide.");

    const { oidc, config, redirectUri } = await getClient();

    // URL complète (BASE_URL + chemin + query)
    const callbackUrl = new URL(`${BASE_URL}${req.originalUrl}`);

    // Échange code -> tokens (Authorization Code Grant)
    const tokenSet = await oidc.authorizationCodeGrant(config, callbackUrl, {
      redirect_uri: redirectUri,
      expectedState: expectedState
    });

    // Récupère l'identité utilisateur
    const idToken = tokenSet?.id_token;
    const accessToken = tokenSet?.access_token;

    if (!idToken) throw new Error("id_token absent du retour OIDC.");

    // Décodage du JWT (debug; sans vérification crypto) pour obtenir au minimum le 'sub'
    const payload = JSON.parse(
      Buffer.from(idToken.split(".")[1], "base64url").toString("utf8")
    );

    const sub = payload.sub || null;
    const iss = payload.iss || "https://accounts.google.com";
    let email = payload.email || null;

    // Si on a un access_token, on utilise UserInfo mais openid-client v6 exige expectedSubject=sub
    if (accessToken && typeof oidc.fetchUserInfo === "function" && sub) {
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
    try { await insertEvent(baseEvent); } catch {}
    console.error("ERROR in callback:", e);
    res.status(400).send(render(tplErr, { MSG: baseEvent.failure_reason }));
  }
});

// Healthcheck
app.get("/healthz", (req, res) => res.json({ ok: true }));

// 404 helper (utile en debug)
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

  // Purge daily (simple in-process scheduler)
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
