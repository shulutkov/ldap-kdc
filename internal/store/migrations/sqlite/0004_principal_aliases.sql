-- Further names a principal answers to.
--
-- FreeIPA keeps krbPrincipalName multivalued and names the real one in krbCanonicalName, which is
-- what lets one account be reached as several names and lets a client canonicalise between them.
-- The relationship is the same here: the principal row holds the canonical name, this table holds
-- the rest. A name is unique across the realm, and since the canonical names live in the other
-- table, the half of that uniqueness which spans both is enforced in Go under the write lock.
CREATE TABLE principal_aliases (
    principal_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    realm        TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (realm, name)
) STRICT, WITHOUT ROWID;

CREATE INDEX principal_aliases_principal_idx ON principal_aliases (principal_id);
