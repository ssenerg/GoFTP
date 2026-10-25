-- Folders that users share from their homes with other users, to read or,
-- with can_write, to change too (see auth.FolderShare). path is the URL
-- path where the folder really is; it follows the folder when it moves
-- within its home, and the share ends when it is deleted or leaves.
CREATE TABLE folder_shares (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    path       TEXT NOT NULL CHECK (path LIKE '/%'),
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    can_write  BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (path, user_id),
    CHECK (user_id <> owner_id)
);
CREATE INDEX folder_shares_user_id_idx ON folder_shares (user_id);
CREATE INDEX folder_shares_owner_id_idx ON folder_shares (owner_id);
