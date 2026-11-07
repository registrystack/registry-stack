// SPDX-License-Identifier: Apache-2.0
//! Test credentials: keys, certificates, issuers, wallets, and presentations
//! are all generated here with the platform signer and `rcgen`.
#![allow(dead_code)]

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use registry_evidence_presentation::{
    ChannelPolicy, IssuerTrust, KeySource, SessionContext, TrustEntry,
};
use registry_platform_crypto::{
    generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk,
};
use registry_platform_x509::{ChainPolicy, TrustAnchors};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

pub const NOW: i64 = 1_800_000_000;
pub const ISS: &str = "https://issuer.example";
pub const VCT: &str = "https://issuer.example/vct/income";
pub const CLIENT_ID: &str = "x509_san_dns:verifier.example";
pub const NONCE: &str = "nonce-7d1f3a9c";
pub const ENTRY_ID: &str = "issuer-a";

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

pub fn private_key(algorithm: GeneratedKeyAlgorithm) -> PrivateJwk {
    generate_private_jwk(algorithm).expect("key")
}

pub fn es256() -> PrivateJwk {
    private_key(GeneratedKeyAlgorithm::Es256)
}

pub fn ed25519() -> PrivateJwk {
    private_key(GeneratedKeyAlgorithm::Ed25519)
}

/// A compact JWS over `header` and `payload`, signed with `key`.
pub fn compact(
    header: &Map<String, Value>,
    payload: &Map<String, Value>,
    key: &PrivateJwk,
) -> String {
    let signing_input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(payload).unwrap())
    );
    let signature = sign(signing_input.as_bytes(), key).expect("signs");
    format!("{signing_input}.{}", b64(&signature))
}

/// An object-property Disclosure and its digest.
pub fn disclosure(salt: &str, name: &str, value: &Value) -> (String, String) {
    encode_disclosure(&json!([salt, name, value]))
}

/// An array-element Disclosure and its digest.
pub fn element_disclosure(salt: &str, value: &Value) -> (String, String) {
    encode_disclosure(&json!([salt, value]))
}

fn encode_disclosure(value: &Value) -> (String, String) {
    let encoded = b64(&serde_json::to_vec(value).unwrap());
    let digest = b64(&Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

pub struct Pki {
    pub root: CertifiedIssuer<'static, KeyPair>,
    pub inter: CertifiedIssuer<'static, KeyPair>,
}

fn ca_params(cn: &str, path_len: Option<u8>) -> CertificateParams {
    let mut params = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    set_validity(&mut params);
    params
}

fn set_validity(params: &mut CertificateParams) {
    let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
    params.not_before = now - Duration::days(30);
    params.not_after = now + Duration::days(365);
}

pub fn pki(name: &str) -> Pki {
    let root = CertifiedIssuer::self_signed(
        ca_params(&format!("{name} root"), None),
        KeyPair::generate().unwrap(),
    )
    .unwrap();
    let inter = CertifiedIssuer::signed_by(
        ca_params(&format!("{name} intermediate"), Some(0)),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    Pki { root, inter }
}

/// PKCS#8 v1 wrapper for a raw Ed25519 seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// An issuer that signs with an Ed25519 leaf certificate whose SAN holds
/// `dns_names` and `uris`.
pub fn x5c_signing(pki: &Pki, dns_names: &[&str], uris: &[&str]) -> (PrivateJwk, Vec<String>) {
    let jwk = ed25519();
    let seed = URL_SAFE_NO_PAD.decode(jwk.d.as_deref().unwrap()).unwrap();
    let der = [ED25519_PKCS8_PREFIX.as_slice(), seed.as_slice()].concat();
    let key = KeyPair::try_from(der.as_slice()).unwrap();
    let mut params = CertificateParams::new(
        dns_names
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for uri in uris {
        params
            .subject_alt_names
            .push(SanType::URI((*uri).try_into().unwrap()));
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "issuer leaf");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    set_validity(&mut params);
    let leaf = params.signed_by(&key, &pki.inter).unwrap();
    let chain = vec![
        STANDARD.encode(leaf.der()),
        STANDARD.encode(pki.inter.der()),
    ];
    (jwk, chain)
}

pub fn anchors(pki: &Pki) -> TrustAnchors {
    TrustAnchors::from_der_certificates(&[pki.root.der().to_vec()]).unwrap()
}

/// How an issuer's key reaches the verifier.
pub struct Issuer {
    pub key: PrivateJwk,
    pub header: Map<String, Value>,
    pub key_source: KeySource,
}

impl Issuer {
    /// An ES256 issuer whose public key is pinned under `kid`.
    pub fn pinned() -> Self {
        let key = es256();
        let mut public = key.public();
        public.kid = Some("issuer-key-1".to_owned());
        // Issuer JWKS entries usually omit `alg`.
        public.alg = None;
        Self {
            header: object(json!({"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-key-1"})),
            key,
            key_source: KeySource::Jwks(vec![public]),
        }
    }

    /// An Ed25519 issuer with an `x5c` chain to `pki`.
    pub fn certified(pki: &Pki, dns_names: &[&str], uris: &[&str]) -> Self {
        let (key, chain) = x5c_signing(pki, dns_names, uris);
        Self {
            header: object(json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "x5c": chain})),
            key,
            key_source: KeySource::X5c {
                anchors: anchors(pki),
                policy: ChainPolicy::default(),
            },
        }
    }

    pub fn public_jwk(&self) -> PublicJwk {
        self.key.public()
    }
}

/// One presentation under construction. Fields are public so a test changes
/// exactly the part it exercises.
pub struct Scenario {
    pub issuer: Issuer,
    pub issuer_id: String,
    pub trusted_issuer: String,
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub disclosures: Vec<String>,
    pub holder: PrivateJwk,
    /// `None` omits the key-binding JWT.
    pub kb_payload: Option<Map<String, Value>>,
    pub kb_header: Map<String, Value>,
    pub kb_key: Option<PrivateJwk>,
    pub entry_vct: Vec<String>,
    counter: usize,
}

impl Scenario {
    pub fn new(issuer: Issuer) -> Self {
        let holder = es256();
        let mut holder_public = serde_json::to_value(holder.public()).unwrap();
        // Wallets publish the holder key without `kid` or `alg`.
        holder_public.as_object_mut().unwrap().remove("kid");
        holder_public.as_object_mut().unwrap().remove("alg");
        let payload = object(json!({
            "iss": ISS,
            "vct": VCT,
            "iat": NOW - 100,
            "nbf": NOW - 100,
            "exp": NOW + 3600,
            "cnf": {"jwk": holder_public},
        }));
        Self {
            header: issuer.header.clone(),
            issuer,
            issuer_id: ENTRY_ID.to_owned(),
            trusted_issuer: ISS.to_owned(),
            payload,
            disclosures: Vec::new(),
            holder,
            kb_payload: Some(Map::new()),
            kb_header: object(json!({"alg": "ES256", "typ": "kb+jwt"})),
            kb_key: None,
            entry_vct: vec![VCT.to_owned()],
            counter: 0,
        }
    }

    pub fn pinned() -> Self {
        let mut scenario = Self::new(Issuer::pinned());
        scenario.with_default_claims();
        scenario
    }

    pub fn certified() -> Self {
        let pki = pki("a");
        let mut scenario = Self::new(Issuer::certified(&pki, &["issuer.example"], &[]));
        scenario.with_default_claims();
        scenario
    }

    fn with_default_claims(&mut self) {
        self.disclose("family_name", json!("Tane"));
    }

    fn salt(&mut self) -> String {
        self.counter += 1;
        format!("salt-{}", self.counter)
    }

    /// Add an object-property Disclosure to the top level and reference it.
    pub fn disclose(&mut self, name: &str, value: Value) {
        let salt = self.salt();
        let (encoded, digest) = disclosure(&salt, name, &value);
        self.reference(&digest);
        self.disclosures.push(encoded);
    }

    /// Reference `digest` from the top-level `_sd` array.
    pub fn reference(&mut self, digest: &str) {
        let sd = self
            .payload
            .entry("_sd")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap();
        sd.push(json!(digest));
        self.payload.insert("_sd_alg".to_owned(), json!("sha-256"));
    }

    pub fn issuer_jwt(&self) -> String {
        compact(&self.header, &self.payload, &self.issuer.key)
    }

    /// `jwt~d1~...~`, the part `sd_hash` covers.
    pub fn sd_jwt(&self) -> String {
        let mut out = self.issuer_jwt();
        out.push('~');
        for disclosure in &self.disclosures {
            out.push_str(disclosure);
            out.push('~');
        }
        out
    }

    pub fn build(&self) -> String {
        let mut out = self.sd_jwt();
        if let Some(overrides) = &self.kb_payload {
            let mut claims = object(json!({
                "iat": NOW,
                "aud": CLIENT_ID,
                "nonce": NONCE,
                "sd_hash": b64(&Sha256::digest(out.as_bytes())),
            }));
            for (name, value) in overrides {
                if value.is_null() {
                    claims.remove(name);
                } else {
                    claims.insert(name.clone(), value.clone());
                }
            }
            let key = self.kb_key.as_ref().unwrap_or(&self.holder);
            out.push_str(&compact(&self.kb_header, &claims, key));
        }
        out
    }

    pub fn trust(&self) -> IssuerTrust {
        IssuerTrust::new(vec![TrustEntry {
            id: self.issuer_id.clone(),
            issuer: self.trusted_issuer.clone(),
            vct: self.entry_vct.clone(),
            key_source: self.issuer.key_source.clone(),
        }])
        .expect("trust")
    }
}

pub fn ctx() -> SessionContext {
    SessionContext {
        nonce: NONCE.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        received_at: NOW,
    }
}

pub fn policy(key_binding_required: bool) -> ChannelPolicy {
    ChannelPolicy::new(vec![VCT.to_owned()], key_binding_required)
}
