-- Two-factor sign-in: the TOTP secret (RFC 6238) of users who turned it on,
-- one being set up until a code of it comes, and the last time step a code
-- was used for, so that none works twice. Recovery codes work once each;
-- only the SHA-256 of each is kept.
ALTER TABLE users
    ADD COLUMN totp_secret  BYTEA,
    ADD COLUMN totp_pending BYTEA,
    ADD COLUMN totp_step    BIGINT NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    user_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
