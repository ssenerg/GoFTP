-- Links can let people upload into a folder instead of reading it, may be
-- used a limited number of times (downloads, or files uploaded), and
-- remember how often and when they were last used.
ALTER TABLE shares
    ADD COLUMN upload       BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN max_uses     INTEGER NOT NULL DEFAULT 0 CHECK (max_uses >= 0), -- 0: no limit
    ADD COLUMN uses         INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN last_used_at TIMESTAMPTZ;

-- Uploads through an upload link have its rights, while it works. Not a
-- foreign key: the uploads of a revoked link fail once continued.
ALTER TABLE uploads ADD COLUMN share_id BIGINT NOT NULL DEFAULT 0;
