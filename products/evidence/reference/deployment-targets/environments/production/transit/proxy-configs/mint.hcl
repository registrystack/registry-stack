pid_file = "/run/registry-mint/transit-proxy.pid"

vault {
  address = "https://vault.example.org:8200"
  ca_cert = "/etc/registry-mint/transit/ca.pem"
  retry {
    num_retries = -1
  }
}

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role       = "registry-mint-production"
      token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    }
  }
}

api_proxy {
  use_auto_auth_token = "force"
}

listener "unix" {
  address                = "/run/registry-mint/transit-proxy.sock"
  tls_disable            = true
  socket_mode            = "0660"
  socket_user            = "vault"
  socket_group           = "registry-mint"
  require_request_header = true
}
