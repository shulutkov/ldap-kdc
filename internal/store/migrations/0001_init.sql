-- Directory objects and Kerberos key material.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL COLLATE NOCASE,
    gid_number  INTEGER NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX groups_name_idx ON groups (name);
CREATE UNIQUE INDEX groups_gid_idx ON groups (gid_number);

-- A group may include another group; membership is resolved transitively at read time.
CREATE TABLE group_includes (
    group_id     INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    included_gid INTEGER NOT NULL,
    PRIMARY KEY (group_id, included_gid)
) STRICT, WITHOUT ROWID;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL COLLATE NOCASE,
    uid_number    INTEGER NOT NULL,
    primary_group INTEGER NOT NULL,
    given_name    TEXT    NOT NULL DEFAULT '',
    sn            TEXT    NOT NULL DEFAULT '',
    mail          TEXT    NOT NULL DEFAULT '',
    login_shell   TEXT    NOT NULL DEFAULT '',
    home_dir      TEXT    NOT NULL DEFAULT '',
    disabled      INTEGER NOT NULL DEFAULT 0,
    pass_bcrypt   TEXT    NOT NULL DEFAULT '',
    otp_secret    TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX users_name_idx ON users (name);
CREATE UNIQUE INDEX users_uid_idx ON users (uid_number);

CREATE TABLE user_groups (
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    gid_number INTEGER NOT NULL,
    PRIMARY KEY (user_id, gid_number)
) STRICT, WITHOUT ROWID;

CREATE TABLE user_ssh_keys (
    user_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    key      TEXT    NOT NULL,
    PRIMARY KEY (user_id, position)
) STRICT, WITHOUT ROWID;

CREATE TABLE user_attrs (
    user_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name     TEXT    NOT NULL,
    position INTEGER NOT NULL,
    value    TEXT    NOT NULL,
    PRIMARY KEY (user_id, name, position)
) STRICT, WITHOUT ROWID;

CREATE TABLE user_app_passwords (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    hash       TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX user_app_passwords_user_idx ON user_app_passwords (user_id);

-- Capabilities belong to either a user or a group; owner_kind says which table owner_id refers to.
CREATE TABLE capabilities (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_kind TEXT    NOT NULL CHECK (owner_kind IN ('user', 'group')),
    owner_id   INTEGER NOT NULL,
    action     TEXT    NOT NULL,
    object     TEXT    NOT NULL
) STRICT;

CREATE INDEX capabilities_owner_idx ON capabilities (owner_kind, owner_id);

CREATE TABLE principals (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT    NOT NULL,
    realm                 TEXT    NOT NULL,
    user_id               INTEGER REFERENCES users (id) ON DELETE CASCADE,
    kvno                  INTEGER NOT NULL DEFAULT 1,
    enabled               INTEGER NOT NULL DEFAULT 1,
    requires_preauth      INTEGER NOT NULL DEFAULT 1,
    allow_forwardable     INTEGER NOT NULL DEFAULT 1,
    allow_proxiable       INTEGER NOT NULL DEFAULT 1,
    allow_renewable       INTEGER NOT NULL DEFAULT 1,
    allow_postdate        INTEGER NOT NULL DEFAULT 0,
    ok_as_delegate        INTEGER NOT NULL DEFAULT 0,
    allow_tgt_based_auth  INTEGER NOT NULL DEFAULT 0,
    max_ticket_life       INTEGER NOT NULL DEFAULT 0,
    max_renewable_life    INTEGER NOT NULL DEFAULT 0,
    password_last_set     INTEGER,
    password_expires_at   INTEGER,
    expires_at            INTEGER,
    locked_until          INTEGER,
    fail_count            INTEGER NOT NULL DEFAULT 0,
    last_success          INTEGER,
    last_failure          INTEGER,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX principals_name_idx ON principals (name, realm);
CREATE INDEX principals_user_idx ON principals (user_id);

-- Long-term keys. Several kvnos may coexist so that tickets issued under the previous key can
-- still be decrypted while services pick up the new one.
CREATE TABLE principal_keys (
    principal_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    kvno         INTEGER NOT NULL,
    etype        INTEGER NOT NULL,
    position     INTEGER NOT NULL DEFAULT 0,
    key          BLOB    NOT NULL,
    salt         TEXT    NOT NULL DEFAULT '',
    s2kparams    TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (principal_id, kvno, etype)
) STRICT, WITHOUT ROWID;

CREATE TABLE delegation_targets (
    principal_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    target       TEXT    NOT NULL,
    PRIMARY KEY (principal_id, target)
) STRICT, WITHOUT ROWID;

CREATE TABLE trusts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_realm TEXT    NOT NULL,
    direction    TEXT    NOT NULL CHECK (direction IN ('outbound', 'inbound', 'bidirectional')),
    transitive   INTEGER NOT NULL DEFAULT 1,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX trusts_realm_idx ON trusts (remote_realm);
