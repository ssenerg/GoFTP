-- Folder shares may end on their own: NULL for never.
ALTER TABLE folder_shares ADD COLUMN expires_at TIMESTAMPTZ;
