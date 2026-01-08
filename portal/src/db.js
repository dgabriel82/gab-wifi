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
  // Create tables if not present (idempotent)
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
    evt.event_id, evt.result, evt.failure_reason,
    evt.oidc_issuer, evt.oidc_sub, evt.email,
    evt.client_mac, evt.ap_mac, evt.ssid,
    evt.client_ip, evt.user_agent,
    evt.consent_version, evt.consented_at, evt.retention_days,
    evt.duration_granted_minutes
  ];
  await p.query(q, v);
}

async function purgeOldEvents() {
  const retention = parseInt(process.env.RETENTION_DAYS || "180", 10);
  const p = getPool();
  await p.query(`DELETE FROM wifi_auth_events WHERE created_at < now() - ($1 || ' days')::interval`, [retention]);
}

module.exports = { initIfNeeded, insertEvent, purgeOldEvents };
