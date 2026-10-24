-- A user's home may hold at most home_quota bytes, along with what its user
-- deleted from it that waits in the trash. NULL takes the server's default
-- (homes.quota); 0 means no limit.
ALTER TABLE users ADD COLUMN home_quota BIGINT CHECK (home_quota >= 0);

-- Upload links count the bytes sent through them, and may stop taking files
-- at max_bytes (0: no limit). A resumable upload counts its whole length
-- when it starts, and gives it back if it ends without a file.
ALTER TABLE shares
    ADD COLUMN max_bytes BIGINT NOT NULL DEFAULT 0 CHECK (max_bytes >= 0),
    ADD COLUMN bytes     BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0);
