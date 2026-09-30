-- Phase 5.5: server-side filtering and keyset pagination of the fleet.
--
-- The listing orders by (lower(hostname), id) and pages with a cursor on
-- that pair, so page N costs the same as page 1. Offset pagination would
-- scan and discard every earlier row, which is the cost that grows with the
-- fleet.
CREATE INDEX IF NOT EXISTS devices_listing_idx ON devices (lower(hostname), id);
CREATE INDEX IF NOT EXISTS devices_platform_idx ON devices (platform);
