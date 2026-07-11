use crate::*;

pub(crate) fn hash_api_key(
    stdin: bool,
    hash_only: bool,
    print_secret: bool,
    api_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = if stdin {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim_end_matches(['\r', '\n']).to_string()
    } else {
        api_key.unwrap_or_else(|| random_secret("rn_api"))
    };
    if api_key.trim().is_empty() {
        return Err("api key must not be empty".into());
    }
    let hash = sha256_hash(&api_key);
    if hash_only {
        println!("{hash}");
    } else if print_secret {
        println!("api_key={api_key}");
        println!("hash={hash}");
    } else if stdin {
        println!("{hash}");
    } else {
        println!("hash={hash}");
        println!("plaintext key generated; rerun with --print-secret to display it");
    }
    Ok(())
}

pub(crate) fn random_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness is available");
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn sha256_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hash = String::with_capacity("sha256:".len() + digest.len() * 2);
    hash.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hash, "{byte:02x}").expect("writing to string cannot fail");
    }
    hash
}

pub(crate) fn demo_issuer_jwk(kid: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": kid,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
    });
    let serialized = serde_json::to_string(&jwk)?;
    PrivateJwk::parse(&serialized)?;
    Ok(serialized)
}
#[cfg(test)]
#[path = "api_key/tests.rs"]
mod tests;
