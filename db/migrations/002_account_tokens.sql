CREATE TABLE IF NOT EXISTS account_action_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_reset')),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS account_action_tokens_user_purpose_idx
  ON account_action_tokens(user_id, purpose, created_at DESC);
CREATE INDEX IF NOT EXISTS account_action_tokens_expiry_idx
  ON account_action_tokens(expires_at);
