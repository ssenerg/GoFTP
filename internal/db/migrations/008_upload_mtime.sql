-- The modification time a resumable upload's file gets once complete, as
-- its sender gave it (e.g. a sync app); NULL for when it is stored.
ALTER TABLE uploads ADD COLUMN mtime TIMESTAMPTZ;
