-- Add risk_delta column to behavior_diffs (Direction 10 — 4-tier severity)
-- Run in Supabase SQL Editor after 001_baseline_schema.sql

ALTER TABLE behavior_diffs
    ADD COLUMN IF NOT EXISTS risk_delta TEXT;

CREATE INDEX IF NOT EXISTS behavior_diffs_risk_delta_idx
    ON behavior_diffs (risk_delta)
    WHERE risk_delta IS NOT NULL;
