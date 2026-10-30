-- Security identifiers, allocated once per object rather than derived on the fly.
--
-- The RID space is shared by users and groups, while the POSIX uid and gid spaces are independent,
-- so deriving a RID from the POSIX id alone hands the same SID to a user and a group that happen
-- to share a number. FreeIPA solves this with a primary and a secondary RID base and an allocation
-- that falls back to the second when the first is taken; the primary key here is what detects the
-- collision.
CREATE TABLE security_identifiers (
    rid        INTEGER PRIMARY KEY,
    owner_kind TEXT    NOT NULL CHECK (owner_kind IN ('user', 'group')),
    owner_id   INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX security_identifiers_owner_idx ON security_identifiers (owner_kind, owner_id);

-- MIT and FreeIPA call the flag that lets a service use protocol transition
-- OK_TO_AUTH_AS_DELEGATE. The previous name described DISALLOW_TGT_BASED, which is a different
-- flag entirely: it says a service may not be reached through a TGS request at all.
ALTER TABLE principals RENAME COLUMN allow_tgt_based_auth TO ok_to_auth_as_delegate;

-- FreeIPA's ipaAllowToImpersonate: the principals a service may act on behalf of. An empty list
-- means any principal, which is what a missing attribute means there.
CREATE TABLE impersonation_targets (
    principal_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    target       TEXT    NOT NULL,
    PRIMARY KEY (principal_id, target)
) STRICT, WITHOUT ROWID;
