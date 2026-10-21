-- Certificates issued to accounts by an external authority and imported through the API.
--
-- What lives here is the public record -- the certificate itself, its serial and its validity
-- window -- so a certificate can be listed, matched back to its owner, and published in the
-- directory as userCertificate;binary. The serial is whatever the issuing authority put on the
-- certificate, kept as lowercase hexadecimal padded to an even number of digits, because an
-- external authority's serials (Vault issues 160-bit ones) do not fit into an integer. There is
-- no revocation: this service runs no authority of its own, so a certificate that should no
-- longer be honored is deleted while its issuer answers for the revocation.
CREATE TABLE user_certificates (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    serial     TEXT    NOT NULL UNIQUE,
    subject    TEXT    NOT NULL,
    der        BLOB    NOT NULL,
    not_before INTEGER NOT NULL,
    not_after  INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX user_certificates_user_idx ON user_certificates (user_id);
