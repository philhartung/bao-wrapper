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

initialize "secret_engines" {
  request "mount_integration_kv_v2" {
    operation = "create"
    path      = "sys/mounts/kv"
    data = {
      type = "kv"
      options = {
        version = "2"
      }
    }
  }

  request "mount_integration_kv_v1" {
    operation = "create"
    path      = "sys/mounts/kvv1"
    data = {
      type = "kv"
      options = {
        version = "1"
      }
    }
  }

  request "seed_integration_kv_v2" {
    operation = "create"
    path      = "kv/data/integration/app"
    data = {
      data = {
        password          = "integration-db-password-7c21"
        password_extended = "integration-db-password-7c21-extended-f84a"
        certificate       = "integration-certificate-material-4e98"
        retries           = 7
        enabled           = true
      }
    }
  }

  request "seed_integration_template" {
    operation = "create"
    path      = "kv/data/integration/template"
    data = {
      data = {
        tpl = <<EOT
database_password={{ secret "kv://password@kv/integration/app" }}
legacy_token={{ secret "legacy://token@kvv1/integration/legacy" }}
mode=production
EOT
      }
    }
  }

  request "seed_integration_kv_v1" {
    operation = "create"
    path      = "kvv1/integration/legacy"
    data = {
      token = "integration-legacy-token-a913"
    }
  }
}

initialize "integration_authentication" {
  request "create_integration_policy" {
    operation = "create"
    path      = "sys/policies/acl/bao-wrapper-integration"
    data = {
      policy = <<EOT
path "kv/data/integration/*" {
  capabilities = ["read"]
}

path "kvv1/integration/*" {
  capabilities = ["read"]
}
EOT
    }
  }

  request "mount_integration_approle" {
    operation = "create"
    path      = "sys/auth/approle"
    data = {
      type = "approle"
    }
  }

  request "create_integration_approle" {
    operation = "create"
    path      = "auth/approle/role/bao-wrapper-integration"
    data = {
      role_id = {
        eval_source    = "env"
        eval_type      = "string"
        env_var        = "INTEGRATION_ROLE_ID"
        require_present = true
      }
      token_policies = ["bao-wrapper-integration"]
      token_ttl      = "5m"
      token_max_ttl  = "10m"
    }
  }

  request "create_integration_secret_id" {
    operation = "update"
    path      = "auth/approle/role/bao-wrapper-integration/custom-secret-id"
    data = {
      secret_id = {
        eval_source     = "env"
        eval_type       = "string"
        env_var         = "INTEGRATION_SECRET_ID"
        require_present = true
      }
    }
  }
}
