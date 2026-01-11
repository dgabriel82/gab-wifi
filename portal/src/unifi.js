const axios = require("axios");
const https = require("https");

const UNIFI_BASE_URL = process.env.UNIFI_CONTROLLER_URL; // ex: https://192.168.1.1
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const USERNAME = process.env.UNIFI_USERNAME;
const PASSWORD = process.env.UNIFI_PASSWORD;

const INSECURE_TLS = (process.env.UNIFI_INSECURE_TLS || "true").toLowerCase() === "true";

if (!UNIFI_BASE_URL || !USERNAME || !PASSWORD) {
  throw new Error("UNIFI_CONTROLLER_URL / UNIFI_USERNAME / UNIFI_PASSWORD manquants");
}

const httpsAgent = new https.Agent({
  rejectUnauthorized: !INSECURE_TLS,
});

const client = axios.create({
  baseURL: UNIFI_BASE_URL,
  timeout: 10000,
  httpsAgent,
  headers: { "Content-Type": "application/json" },
  validateStatus: () => true,
});

let cookieHeader = null; // ex: "TOKEN=...."
let csrfToken = null;    // ex: "5ad0...."

function extractTokenCookie(setCookieHeaders) {
  if (!setCookieHeaders) return null;
  const arr = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

  // on ne garde que le cookie TOKEN=...
  const token = arr
    .map((c) => String(c).split(";")[0].trim())
    .find((kv) => kv.startsWith("TOKEN="));

  return token || null;
}

async function login() {
  const res = await client.post("/api/auth/login", {
    username: USERNAME,
    password: PASSWORD,
    remember: true,
  });

  if (res.status !== 200) {
    const code = res?.data?.code;
    const msg = res?.data?.message;
    throw new Error(`UniFi login failed (${res.status}) ${code || ""} ${msg || ""}`.trim());
  }

  const tokenCookie = extractTokenCookie(res.headers?.["set-cookie"]);
  if (!tokenCookie) throw new Error("UniFi login OK mais cookie TOKEN absent.");

  cookieHeader = tokenCookie;

  // UniFi OS renvoie le CSRF token dans les headers
  csrfToken =
    res.headers?.["x-updated-csrf-token"] ||
    res.headers?.["x-csrf-token"] ||
    null;

  if (!csrfToken) {
    // parfois pas strictement nécessaire selon endpoint, mais pour /proxy/network c'est souvent requis
    throw new Error("UniFi login OK mais CSRF token absent (x-csrf-token).");
  }

  return true;
}

async function postNetwork(path, body) {
  if (!cookieHeader || !csrfToken) await login();

  const res = await client.post(path, body, {
    headers: {
      Cookie: cookieHeader,
      "X-Csrf-Token": csrfToken,
    },
  });

  // Session expirée -> relogin + retry une fois
  if (res.status === 401 || res.status === 403) {
    cookieHeader = null;
    csrfToken = null;
    await login();

    const retry = await client.post(path, body, {
      headers: {
        Cookie: cookieHeader,
        "X-Csrf-Token": csrfToken,
      },
    });
    return retry;
  }

  return res;
}

async function authorizeGuest(mac, minutes) {
  if (!mac) throw new Error("MAC manquante pour authorizeGuest");

  const res = await postNetwork(`/proxy/network/api/s/${UNIFI_SITE}/cmd/stamgr`, {
    cmd: "authorize-guest",
    mac,
    minutes,
  });

  if (res.status !== 200 || res.data?.meta?.rc !== "ok") {
    throw new Error(`UniFi authorize-guest failed: status=${res.status} body=${JSON.stringify(res.data)}`);
  }

  return true;
}

module.exports = { authorizeGuest };
