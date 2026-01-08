require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const { getClient } = require("./oidc");
const { insertEvent, initIfNeeded, purgeOldEvents } = require("./db");
const { authorizeGuest } = require("./unifi");

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "change-me"));

const PORT = parseInt(process.env.PORT || "3000", 10);
const BASE_URL = process.env.BASE_URL;
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || "180", 10);
const CONSENT_VERSION = process.env.CONSENT_VERSION || "1.0";
const DEFAULT_MINUTES = parseInt(process.env.DEFAULT_MINUTES || "480", 10);

// Store pending captive params in a signed cookie (short-lived)
function setPending(res, obj) {
  res.cookie("pending", JSON.stringify(obj), {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    secure: true,
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

const fs = require("fs");
const path = require("path");
const tplIndex = fs.readFileSync(path.join(__dirname, "views", "index.html"), "utf8");
const tplOk = fs.readFileSync(path.join(__dirname, "views", "ok.html"), "utf8");
const tplErr = fs.readFileSync(path.join(__dirname, "views", "error.html"), "utf8");

app.get("/", async (req, res) => {
  // UniFi captive usually provides params like: id, ap, ssid, mac, url, etc.
  const pending = {
    mac: (req.query.mac || req.query.client_mac || "").toString(),
    ap: (req.query.ap || req.query.ap_mac || "").toString(),
    ssid: (req.query.ssid || "").toString(),
    // keep original query for debugging if needed (do not store long-term)
    q: Object.fromEntries(Object.entries(req.query).slice(0, 30))
  };

  // Save it for the subsequent POST /start
  setPending(res, pending);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(render(tplIndex, { RETENTION_DAYS }));
});

app.post("/start", async (req, res) => {
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

  // Mark consent timestamp in cookie state too
  pending.consented_at = new Date().toISOString();
  setPending(res, pending);

  const oidc = await getClient();

  const state = uuidv4();
  // store state in a signed cookie (short-lived)
  res.cookie("oidc_state", state, {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    maxAge: 10 * 60 * 1000
  });

  const authUrl = oidc.authorizationUrl({
    scope: "openid email",
    state,
    prompt: "select_account"
  });

  res.redirect(authUrl);
});

app.get("/auth/google/callback", async (req, res) => {
  const event_id = uuidv4();
  const userAgent = req.get("user-agent") || null;
  const clientIp = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim()
    || req.socket.remoteAddress
    || null;

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

    const oidc = await getClient();

    const params = oidc.callbackParams(req);
    const tokenSet = await oidc.callback(process.env.GOOGLE_REDIRECT_URI, params, { state: expectedState });

    const claims = tokenSet.claims();

    baseEvent.oidc_issuer = claims.iss || "https://accounts.google.com";
    baseEvent.oidc_sub = claims.sub || null;
    baseEvent.email = claims.email || null;

    // Authorize client in UniFi
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
    res.status(400).send(render(tplErr, { MSG: baseEvent.failure_reason }));
  }
});

// Simple healthcheck
app.get("/healthz", (req, res) => res.json({ ok: true }));

async function main() {
  if (!BASE_URL) {
    console.error("BASE_URL missing (e.g. https://gab-wifi.duckdns.org)");
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL missing");
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
