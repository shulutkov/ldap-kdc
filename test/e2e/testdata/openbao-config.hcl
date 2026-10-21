# The stand's OpenBao: in-memory storage, plain HTTP, the plugin directory the image was built
# with, and an auto-unseal against the SoftHSM token initialized at image build. The pkcs11 KMS
# plugin is declared rather than registered through the API — a seal plugin has to exist before
# the server unseals, which is before any API call could be made.
storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr         = "http://127.0.0.1:8200"
plugin_directory = "/openbao/plugins"

plugin "kms" "pkcs11" {
  command = "openbao-plugin-kms-pkcs11"
  version = "v0.2.1"
}

seal "pkcs11" {
  lib         = "/usr/lib/softhsm/libsofthsm2.so"
  token_label = "openbao"
  pin         = "1234"
  key_label   = "bao-root-key-aes"
}
