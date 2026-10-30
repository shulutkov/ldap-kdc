-- The realm's DNS records.
--
-- Values are kept in presentation form -- "192.0.2.10", "0 100 88 kdc.example.com." -- and parsed
-- with the DNS library's own parser when a record is served. That keeps one column for every
-- record type and puts the syntax rules where they already exist, rather than reimplementing them
-- per type here.
CREATE TABLE dns_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    type       TEXT    NOT NULL,
    ttl        INTEGER NOT NULL,
    value      TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX dns_records_name_idx ON dns_records (name, type);

-- The same value twice at one name is not a second record, it is a duplicate answer.
CREATE UNIQUE INDEX dns_records_value_idx ON dns_records (name, type, value);

-- Reverse lookups are answered by finding the address record that holds the address, so they need
-- an index on the value rather than a second copy of the data as a PTR row.
CREATE INDEX dns_records_address_idx ON dns_records (type, value);
