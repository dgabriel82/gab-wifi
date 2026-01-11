let cached;

async function getClient() {
  if (cached) return cached;

  const oidc = await import("openid-client");

  if (typeof oidc.discovery !== "function") {
    throw new Error("openid-client v6: discovery() introuvable");
  }

  const issuerBase = new URL("https://accounts.google.com");

  // v6: discovery() retourne une "Configuration"
  // client_id / client_secret sont passés ici (client auth explicite en v6)
  const config = await oidc.discovery(
    issuerBase,
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET
  );

  cached = {
    oidc,
    config,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
  };

  return cached;
}

module.exports = { getClient };
