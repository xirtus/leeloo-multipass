CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE passport_principals (
 id text PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 200),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE passport_network_accounts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 principal_id text NOT NULL REFERENCES passport_principals(id) ON DELETE CASCADE,
 provider text NOT NULL CHECK(provider IN ('bluesky','mastodon','matrix','fediverse')),
 network text NOT NULL,
 address text NOT NULL,
 subject text,
 profile_url text NOT NULL,
 added_at timestamptz NOT NULL DEFAULT now(),
 verified_at timestamptz,
 UNIQUE(principal_id,provider,address)
);
CREATE UNIQUE INDEX passport_network_verified_owner ON passport_network_accounts(provider,network,subject) WHERE verified_at IS NOT NULL;
CREATE INDEX passport_network_principal ON passport_network_accounts(principal_id);
CREATE TABLE passport_network_state (
 key text PRIMARY KEY,
 ciphertext text NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE INDEX passport_network_state_expiry ON passport_network_state(expires_at);
CREATE TABLE passport_audit_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 principal_id text NOT NULL REFERENCES passport_principals(id) ON DELETE CASCADE,
 action text NOT NULL,
 target text,
 created_at timestamptz NOT NULL DEFAULT now()
);
