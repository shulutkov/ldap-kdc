-- Records registered automatically, and a zone serial that moves with every change.
--
-- origin says who put a record in the zone. Empty is an administrator, through the REST API or
-- the bootstrap plan; "docker:<container id>" is the container registration that tracks a running
-- container on a configured network. The two never share a name: a name an administrator has
-- already claimed is left to them.
ALTER TABLE dns_records ADD COLUMN origin TEXT NOT NULL DEFAULT '';

CREATE INDEX dns_records_origin_idx ON dns_records (origin);

-- The SOA serial. It was the time of the latest insert, which a deletion does not move: removing
-- the newest record left the serial where it was, and a secondary comparing serials never learned
-- of the removal. The serial now only ever grows, and every change to the zone raises it.
CREATE TABLE dns_zone (
    id     BIGINT PRIMARY KEY CHECK (id = 1),
    serial BIGINT NOT NULL
);

-- Starts where the old serial stood: the time of the latest record change, or zero for an empty
-- zone, so an upgrade does not move the serial backwards.
INSERT INTO dns_zone (id, serial)
VALUES (1, COALESCE((SELECT MAX(updated_at) FROM dns_records), 0));
