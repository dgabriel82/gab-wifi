const { Pool } = require("pg");

let pool;

function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
    });
  }
  return pool;
}

async function initIfNeeded() {
  const p = getPool();

  await p.query(`
    CREATE TABLE IF NOT EXISTS wifi_auth_events (
      event_id UUID PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      result TEXT NOT NULL,
      failure_reason TEXT NULL,

      oidc_issuer TEXT NULL,
      oidc_sub TEXT NULL,
      email TEXT NULL,

      client_mac TEXT NULL,
      ap_mac TEXT NULL,
      ssid TEXT NULL,

      client_ip TEXT NULL,
      user_agent TEXT NULL,

      consent_version TEXT NULL,
      consented_at TIMESTAMPTZ NULL,
      retention_days INT NULL,

      duration_granted_minutes INT NULL
    );
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_auth_events_created_at
    ON wifi_auth_events (created_at);
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_auth_events_oidc_sub
    ON wifi_auth_events (oidc_sub);
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_auth_events_email
    ON wifi_auth_events (email);
  `);

  await p.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_auth_events_client_mac
    ON wifi_auth_events (client_mac);
  `);
}

async function insertEvent(evt) {
  const p = getPool();

  const q = `
    INSERT INTO wifi_auth_events (
      event_id, result, failure_reason,
      oidc_issuer, oidc_sub, email,
      client_mac, ap_mac, ssid,
      client_ip, user_agent,
      consent_version, consented_at, retention_days,
      duration_granted_minutes
    ) VALUES (
      $1,$2,$3,
      $4,$5,$6,
      $7,$8,$9,
      $10,$11,
      $12,$13,$14,
      $15
    );
  `;

  const v = [
    evt.event_id,
    evt.result,
    evt.failure_reason,

    evt.oidc_issuer,
    evt.oidc_sub,
    evt.email,

    evt.client_mac,
    evt.ap_mac,
    evt.ssid,

    evt.client_ip,
    evt.user_agent,

    evt.consent_version,
    evt.consented_at,
    evt.retention_days,

    evt.duration_granted_minutes,
  ];

  await p.query(q, v);
}

async function purgeOldEvents() {
  const retention = parseInt(process.env.RETENTION_DAYS || "180", 10);
  const p = getPool();
  await p.query(
    `DELETE FROM wifi_auth_events WHERE created_at < now() - ($1 || ' days')::interval`,
    [retention]
  );
}

/**
 * Renvoie les derniers événements pour l'admin
 * @param {{limit?: number, q?: string, result?: string}} opts
 */
async function listLatestEvents(opts = {}) {
  const limit = Math.min(parseInt(opts.limit || "200", 10) || 200, 1000);
  const q = (opts.q || "").toString().trim();
  const result = (opts.result || "").toString().trim();

  const where = [];
  const params = [];
  let i = 1;

  if (result) {
    where.push(`result = $${i++}`);
    params.push(result);
  }

  if (q) {
    // filtre simple : contient dans email ou mac
    where.push(`(email ILIKE $${i} OR client_mac ILIKE $${i})`);
    params.push(`%${q}%`);
    i++;
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const sql = `
    SELECT
      created_at, result, failure_reason,
      email, client_mac, ssid, ap_mac, client_ip
    FROM wifi_auth_events
    ${whereSql}
    ORDER BY created_at DESC
    LIMIT $${i}
  `;
  params.push(limit);

  const p = getPool();
  const r = await p.query(sql, params);
  return r.rows;
}

module.exports = {
  initIfNeeded,
  insertEvent,
  purgeOldEvents,
  listLatestEvents,
};
