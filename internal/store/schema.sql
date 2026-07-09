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
