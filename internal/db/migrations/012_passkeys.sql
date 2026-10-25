-- Passkeys (WebAuthn credentials) sign their users in without a password.
-- credential holds what checking one takes, as JSON: its public key, sign
-- counter and flags; credential_id is the authenticator's name for it.
CREATE TABLE passkeys (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    credential_id BYTEA NOT NULL UNIQUE,
    credential    BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);
