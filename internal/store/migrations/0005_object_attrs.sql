-- Custom attributes on directory objects, in one table for every kind of object rather than one
-- per kind.
--
-- They carry facts this service has no opinion about -- that an account heads a department, that a
-- group owns a cost centre -- to whatever reads the directory. An authorization policy elsewhere
-- filters on them like any other LDAP attribute, which is the point: the fact is written once,
-- next to the account it describes, instead of in a table the policy engine keeps of its own.
CREATE TABLE object_attrs (
    owner_kind TEXT    NOT NULL CHECK (owner_kind IN ('user', 'group')),
    owner_id   INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    position   INTEGER NOT NULL,
    value      TEXT    NOT NULL,
    PRIMARY KEY (owner_kind, owner_id, name, position)
) STRICT, WITHOUT ROWID;

-- The attributes a user already carries move across unchanged. They are the same facts, and
-- leaving them behind would quietly empty every entry that has one.
INSERT INTO object_attrs (owner_kind, owner_id, name, position, value)
SELECT 'user', user_id, name, position, value FROM user_attrs;

DROP TABLE user_attrs;
