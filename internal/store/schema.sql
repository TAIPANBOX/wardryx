CREATE TABLE IF NOT EXISTS approvals (
    approval_id  TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    decided_by   TEXT,
    decision     TEXT,
    context_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Additive migration style, matching Idryx's internal/graph/schema.sql: every
-- change is an IF NOT EXISTS create or an ADD COLUMN IF NOT EXISTS, so an
-- existing database upgrades in place and re-applying this file is always a
-- no-op.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS run_id TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS context_json JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS approvals_agent_id ON approvals (agent_id);
CREATE INDEX IF NOT EXISTS approvals_requested_at ON approvals (requested_at);

-- WARDRYX_APPROVAL_SINGLE_USE redemption tracking. A minted approval_token's
-- claims do not carry its originating approval_id (see
-- internal/approval.RedemptionKey), so a redemption cannot be recorded as a
-- redeemed_at column on the approvals row it came from: /v1/decide never
-- sees that row, only the token. Instead each redemption claims a row here,
-- keyed by a sha256 hex digest of the token string; Store.TryRedeem is an
-- INSERT .. ON CONFLICT DO NOTHING, so the first claim for a given key
-- inserts a row (redeemed_at defaults to now()) and every later claim for
-- the same key affects zero rows -- the atomic check-and-set single-use
-- mode needs, enforced by Postgres itself rather than by a client-side lock.
CREATE TABLE IF NOT EXISTS approval_redemptions (
    redemption_key TEXT PRIMARY KEY,
    redeemed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
