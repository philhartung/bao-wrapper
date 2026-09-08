# This configuration is exclusively for local and CI integration tests. The
# static seal key and AppRole credentials are intentionally public fixtures and
# must never be reused outside this disposable environment.

disable_mlock = true
api_addr      = "http://127.0.0.1:8200"

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/openbao/data"
}

seal "static" {
  current_key_id = "bao-wrapper-integration-v1"
  current_key    = "env://OPENBAO_STATIC_SEAL_KEY"
}
