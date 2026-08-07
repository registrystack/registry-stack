path "transit/keys/evidence-signing" {
  capabilities = ["read"]
}

path "transit/sign/evidence-signing/sha2-256" {
  capabilities = ["update"]
  required_parameters = ["input", "key_version", "marshaling_algorithm", "prehashed"]
  allowed_parameters = {
    "input"                 = []
    "key_version"           = [7]
    "marshaling_algorithm" = ["jws"]
    "prehashed"             = [true]
  }
}
