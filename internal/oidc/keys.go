package oidc

// MetaSigningKey is where the provider's token signing key lives, sealed with the master key like
// every other secret in the database.
//
// It is the provider's own key and nothing else signs with it. The management API issues its
// administrative sessions under a different one, so an id token a relying party holds can never be
// presented there as an administrator's session: the signature would not be the API's.
const MetaSigningKey = "oidc_signing_key"
