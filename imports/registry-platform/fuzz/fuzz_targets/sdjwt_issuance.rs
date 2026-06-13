#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use registry_platform_crypto::PrivateJwk;
use registry_platform_sdjwt::{Disclosure, HolderConfirmation, SdJwtIssuanceInput, SdJwtIssuer};
use serde::Deserialize;
use serde_json::Value;

const ISSUER_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
const HOLDER_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;

#[derive(Debug, Deserialize)]
struct SeedInput {
    iss: Option<String>,
    sub_ref: Option<String>,
    credential_id: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    vct: Option<String>,
    status: Option<Value>,
    public_claims: Option<BTreeMap<String, Value>>,
    disclosures: Option<Vec<SeedDisclosure>>,
    bind_holder: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SeedDisclosure {
    name: String,
    value: Value,
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 8192);
    let input = match serde_json::from_str::<SeedInput>(&bounded) {
        Ok(seed) => seed.into_issuance_input(),
        Err(_) => bytes_to_issuance_input(data),
    };
    let _ = runtime().block_on(issuer().issue(input));
});

impl SeedInput {
    fn into_issuance_input(self) -> SdJwtIssuanceInput {
        SdJwtIssuanceInput {
            iss: bounded_or_default(self.iss, "did:web:issuer.test", 256),
            sub_ref: bounded_or_default(self.sub_ref, "did:example:subject", 256),
            credential_id: self.credential_id.map(|value| take_chars(&value, 256)),
            iat: self.iat.unwrap_or(1_700_000_000),
            exp: self.exp.unwrap_or(1_700_000_600),
            vct: bounded_or_default(self.vct, "https://vct.example/test", 256),
            status: self.status,
            public_claims: bound_claims(self.public_claims.unwrap_or_default()),
            cnf: self.bind_holder.unwrap_or(false).then(holder_confirmation),
            disclosures: self
                .disclosures
                .unwrap_or_default()
                .into_iter()
                .take(8)
                .map(|disclosure| Disclosure {
                    name: take_chars(&disclosure.name, 128),
                    value: disclosure.value,
                })
                .collect(),
        }
    }
}

fn bytes_to_issuance_input(data: &[u8]) -> SdJwtIssuanceInput {
    let first = data.first().copied().unwrap_or_default();
    let second = data.get(1).copied().unwrap_or_default();
    SdJwtIssuanceInput {
        iss: "did:web:issuer.test".to_string(),
        sub_ref: format!("did:example:subject-{first}"),
        credential_id: (first % 5 == 0).then(|| format!("urn:fuzz:{first:02x}{second:02x}")),
        iat: 1_700_000_000 + i64::from(first),
        exp: 1_700_000_060 + i64::from(second),
        vct: "https://vct.example/test".to_string(),
        status: None,
        public_claims: BTreeMap::new(),
        cnf: (first % 2 == 0).then(holder_confirmation),
        disclosures: vec![Disclosure {
            name: format!("claim-{first}"),
            value: Value::String(take_chars(&String::from_utf8_lossy(data), 128)),
        }],
    }
}

fn issuer() -> &'static SdJwtIssuer {
    static ISSUER: OnceLock<SdJwtIssuer> = OnceLock::new();
    ISSUER.get_or_init(|| {
        let jwk = PrivateJwk::parse(ISSUER_PRIVATE_JWK).expect("issuer private JWK parses");
        SdJwtIssuer::from_jwk(jwk).expect("issuer builds")
    })
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzz runtime builds")
    })
}

fn holder_confirmation() -> HolderConfirmation {
    let holder = PrivateJwk::parse(HOLDER_PRIVATE_JWK).expect("holder private JWK parses");
    HolderConfirmation {
        jwk: holder.public(),
        kid: Some("did:jwk:holder#key-1".to_string()),
    }
}

fn bound_claims(claims: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    claims
        .into_iter()
        .take(8)
        .map(|(name, value)| (take_chars(&name, 128), value))
        .collect()
}

fn bounded_or_default(value: Option<String>, default: &str, limit: usize) -> String {
    value
        .map(|value| take_chars(&value, limit))
        .unwrap_or_else(|| default.to_string())
}

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
