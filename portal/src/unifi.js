const axios = require("axios");
const https = require("https");

const UNIFI_BASE_URL = process.env.UNIFI_CONTROLLER_URL; // ex: https://192.168.1.1
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const USERNAME = process.env.UNIFI_USERNAME;
const PASSWORD = process.env.UNIFI_PASSWORD;

// Autoriser TLS non vérifié UNIQUEMENT pour UniFi (cert auto-signé)
const INSECURE_TLS = (process.env.UNIFI_INSECURE_TLS || "true").toLowerCase() === "true";

if (!UNIFI_BASE_URL || !USERNAME || !PASSWORD) {
  throw new Error("UNIFI_CONTROLLER_URL / UNIFI_USERNAME / UNIFI_PASSWORD manquants");
}

// Agent HTTPS custom
const httpsAgent = new https.Agent({
  rejectUnauthorized: !INSECURE_TLS
});

// Client axios avec cookie jar implicite (axios garde les cookies par instance)
const client = axios.create({
  baseURL: UNIFI_BASE_URL,
  timeout: 10000,
  withCredentials: true,
  httpsAgent,
  headers: {
    "Content-Type": "application/json"
  }
});

/**
 * Login UniFi (UniFi OS)
 * POST /api/auth/login
 */
async function login() {
  await client.post("/api/auth/login", {
    username: USERNAME,
    password: PASSWORD,
    remember: true
  });
}

/**
 * Autorise un client invité
 * @param {string} mac - MAC address du client
 * @param {number} minutes - durée d'autorisation
 */
async function authorizeGuest(mac, minutes) {
  if (!mac) throw new Error("MAC manquante pour authorizeGuest");

  // Login (cookie de session)
  await login();

  // Endpoint UniFi OS + Network
  const url = `/proxy/network/api/s/${UNIFI_SITE}/cmd/stamgr`;

  const payload = {
    cmd: "authorize-guest",
    mac,
    minutes
  };

  const res = await client.post(url, payload);

  if (!res.data || res.data.meta?.rc !== "ok") {
    throw new Error(`Échec authorizeGuest: ${JSON.stringify(res.data)}`);
  }

  return true;
}

module.exports = { authorizeGuest };
