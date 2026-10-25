-- App passwords let apps, such as sync apps over WebDAV, sign in as their
-- user with a password of their own, which can be revoked alone. Only the
-- SHA-256 of each is kept; changing the user's password ends them all.
CREATE TABLE app_passwords (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    token_hash   BYTEA NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX app_passwords_user_id_idx ON app_passwords (user_id);
