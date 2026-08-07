pid_file = "/run/registry-evidence/transit-proxy.pid"

vault {
  address = "https://vault.example.org:8200"
  ca_cert = "/etc/registry-evidence/transit/ca.pem"
  retry {
    num_retries = -1
  }
}

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role       = "registry-evidence-production"
      token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    }
  }
}

api_proxy {
  use_auto_auth_token = "force"
}

listener "unix" {
  address                = "/run/registry-evidence/transit-proxy.sock"
  tls_disable            = true
  socket_mode            = "0660"
  socket_user            = "vault"
  socket_group           = "registry-evidence"
  require_request_header = true
}
