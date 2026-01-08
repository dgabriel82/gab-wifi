const axios = require("axios");
const { wrapper } = require("axios-cookiejar-support");
const { CookieJar } = require("tough-cookie");

function normalizeMac(mac) {
  return (mac || "").trim().toLowerCase();
}

function buildClient(baseURL) {
  const jar = new CookieJar();
  const c = wrapper(axios.create({
    baseURL,
    jar,
    withCredentials: true,
    timeout: 15000,
    validateStatus: () => true
  }));
  return c;
}

async function loginUniFi(client, username, password) {
  // UniFi OS (newer): POST /api/auth/login
  // Legacy: POST /api/login
  const payload = { username, password };

  let r = await client.post("/api/auth/login", payload, {
    headers: { "Content-Type": "application/json" }
  });

  if (r.status >= 200 && r.status < 300) return true;

  // Try legacy
  r = await client.post("/api/login", payload, {
    headers: { "Content-Type": "application/json" }
  });

  if (r.status >= 200 && r.status < 300) return true;

  throw new Error(`UniFi login failed (status ${r.status})`);
}

/**
 * Authorize guest client (MAC) for N minutes.
 * Works on UniFi Network API via /proxy/network/api/s/<site>/cmd/stamgr (UniFi OS) or /api/s/<site>/cmd/stamgr (legacy).
 */
async function authorizeGuest(mac, minutes) {
  const controller = process.env.UNIFI_CONTROLLER_URL; // ex: https://192.168.1.1
  const site = process.env.UNIFI_SITE || "default";
  const username = process.env.UNIFI_USERNAME;
  const password = process.env.UNIFI_PASSWORD;

  if (!controller || !username || !password) {
    throw new Error("UniFi env not set (UNIFI_CONTROLLER_URL/UNIFI_USERNAME/UNIFI_PASSWORD)");
  }

  const m = normalizeMac(mac);
  const nMinutes = Math.max(1, parseInt(minutes || "480", 10)); // default 8h

  const client = buildClient(controller);

  await loginUniFi(client, username, password);

  const body = {
    cmd: "authorize-guest",
    mac: m,
    minutes: nMinutes
  };

  // UniFi OS path
  let r = await client.post(`/proxy/network/api/s/${site}/cmd/stamgr`, body, {
    headers: { "Content-Type": "application/json" }
  });

  if (r.status >= 200 && r.status < 300) return true;

  // Legacy path fallback
  r = await client.post(`/api/s/${site}/cmd/stamgr`, body, {
    headers: { "Content-Type": "application/json" }
  });

  if (r.status >= 200 && r.status < 300) return true;

  throw new Error(`UniFi authorize failed (status ${r.status})`);
}

module.exports = { authorizeGuest };
