path "transit/keys/mint-signing" {
  capabilities = ["read"]
}

path "transit/sign/mint-signing/sha2-256" {
  capabilities = ["update"]
  required_parameters = ["input", "key_version", "marshaling_algorithm", "prehashed"]
  allowed_parameters = {
    "input"                 = []
    "key_version"           = [5]
    "marshaling_algorithm" = ["jws"]
    "prehashed"             = [true]
  }
}
