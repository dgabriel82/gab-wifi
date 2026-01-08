const { Issuer } = require("openid-client");

let client;

async function getClient() {
  if (client) return client;

  const issuer = await Issuer.discover("https://accounts.google.com");
  client = new issuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uris: [process.env.GOOGLE_REDIRECT_URI],
    response_types: ["code"],
  });

  return client;
}

module.exports = { getClient };
