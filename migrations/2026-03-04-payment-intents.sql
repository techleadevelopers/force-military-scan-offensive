-- Payment intents table for PagBank PIX unlocks
CREATE TABLE IF NOT EXISTS payment_intents (
  id               varchar(255) PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          varchar(255) NOT NULL REFERENCES users(id),
  scan_id          varchar(255) REFERENCES scans(id),
  amount_cents     integer NOT NULL,
  currency         text NOT NULL DEFAULT 'BRL',
  status           text NOT NULL DEFAULT 'PENDING',
  gateway          text NOT NULL DEFAULT 'PAGBANK_PIX',
  external_order_id  text,
  external_charge_id text,
  reference_id     text,
  qr_code_text     text,
  qr_code_url      text,
  expires_at       timestamp,
  idempotency_key  text,
  paid_at          timestamp,
  created_at       timestamp DEFAULT now(),
  updated_at       timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_payment_intents_user_scan
  ON payment_intents (user_id, scan_id);

CREATE INDEX IF NOT EXISTS idx_payment_intents_reference
  ON payment_intents (reference_id);

CREATE INDEX IF NOT EXISTS idx_payment_intents_external_charge
  ON payment_intents (external_charge_id);
