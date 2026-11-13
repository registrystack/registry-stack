// SPDX-License-Identifier: Apache-2.0
//! Local signer for owner-requested CLI tokens and the run's browser issuer.

use anyhow::{ensure, Context, Result};
use registry_platform_crypto::{
    generate_private_jwk, jws::sign_compact_jws, GeneratedKeyAlgorithm, LocalJwkSigner, PrivateJwk,
};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

use super::{
    clock,
    plan::{self, Product, TestPerson},
    write_private, RunInput,
};

/// How long a token the local issuer signs stays valid.
pub(super) const TOKEN_LIFETIME_SECONDS: u64 = 300;
/// Browser sessions need enough time to complete a bounded preview journey.
pub(super) const BROWSER_TOKEN_LIFETIME_SECONDS: u64 = 900;

/// When a token issued at `now` expires: one lifetime later, or with the run
/// if that comes first.
pub(super) fn token_expiry(run_expires: u64, now: u64) -> u64 {
    run_expires.min(now.saturating_add(TOKEN_LIFETIME_SECONDS))
}

pub(super) struct Issuer {
    signer: LocalJwkSigner,
    public_jwks: Value,
    runtime: tokio::runtime::Runtime,
}

impl Issuer {
    pub(super) fn create(root: &Path) -> Result<Self> {
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)?;
        let encoded = super::bindings::encode_private_jwk(&key)?;
        write_private(&root.join("issuer-key"), &encoded)?;
        write_private(
            &root.join("jwks"),
            &serde_json::to_vec(&json!({
                "keys": [key.public()]
            }))?,
        )?;
        Self::from_key(key)
    }

    pub(super) fn load(root: &Path) -> Result<Self> {
        let encoded = Zeroizing::new(plan::read(&root.join("issuer-key"), 16 * 1024)?);
        let text = std::str::from_utf8(&encoded).context("invalid local issuer key encoding")?;
        let key =
            PrivateJwk::parse(text).map_err(|_| anyhow::anyhow!("invalid local issuer key"))?;
        Self::from_key(key)
    }

    fn from_key(key: PrivateJwk) -> Result<Self> {
        let public_jwks = json!({"keys": [key.public()]});
        Ok(Self {
            signer: LocalJwkSigner::new(key)?,
            public_jwks,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        })
    }

    pub(super) fn public_jwks(&self) -> Value {
        self.public_jwks.clone()
    }

    pub(super) fn token(
        &self,
        input: &RunInput,
        person: &TestPerson,
        product: Product,
        expires: u64,
    ) -> Result<Zeroizing<String>> {
        self.runtime
            .block_on(self.sign(input, person, product, expires))
    }

    pub(super) async fn sign(
        &self,
        input: &RunInput,
        person: &TestPerson,
        product: Product,
        expires: u64,
    ) -> Result<Zeroizing<String>> {
        self.sign_access(
            input,
            person,
            product,
            &person.client,
            &person.grants[&product].scopes,
            expires,
            TOKEN_LIFETIME_SECONDS,
            None,
        )
        .await
    }

    #[cfg(test)]
    pub(super) fn browser_access_token(
        &self,
        input: &RunInput,
        alias: &str,
        product: Product,
        client_id: &str,
        scopes: &[String],
        run_expires: u64,
    ) -> Result<Zeroizing<String>> {
        self.runtime.block_on(self.sign_browser_access(
            input,
            alias,
            product,
            client_id,
            scopes,
            run_expires,
        ))
    }

    pub(super) async fn sign_browser_access(
        &self,
        input: &RunInput,
        alias: &str,
        product: Product,
        client_id: &str,
        scopes: &[String],
        run_expires: u64,
    ) -> Result<Zeroizing<String>> {
        let person = input
            .plan
            .people
            .get(alias)
            .context("test person is not in the run's plan")?;
        self.sign_access(
            input,
            person,
            product,
            client_id,
            scopes,
            run_expires,
            BROWSER_TOKEN_LIFETIME_SECONDS,
            Some(alias),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_access(
        &self,
        input: &RunInput,
        person: &TestPerson,
        product: Product,
        client_id: &str,
        requested_scopes: &[String],
        run_expires: u64,
        lifetime: u64,
        browser_alias: Option<&str>,
    ) -> Result<Zeroizing<String>> {
        let now = clock()?;
        let expires = run_expires.min(now.saturating_add(lifetime));
        ensure!(expires > now, "the development run has expired");
        let plan = &input.plan;
        let grant = &person.grants[&product];
        let forward_context =
            browser_alias.is_none() && product == Product::Casework && person.casework_context;
        let mut claims = grant.claims.clone();
        let granted: std::collections::BTreeSet<_> = grant.scopes.iter().collect();
        ensure!(
            requested_scopes.iter().all(|scope| granted.contains(scope)),
            "requested scope is not granted to the test person"
        );
        let scopes = requested_scopes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let scope_value = scopes.into_iter().collect::<Vec<_>>().join(" ");
        let audience = if forward_context {
            json!([
                plan.product(product).audience,
                plan.product(Product::Breg).audience
            ])
        } else {
            json!(plan.product(product).audience)
        };
        if product == Product::Breg || forward_context {
            let authority = input.breg_authority.as_ref().expect("BReg authority");
            claims.insert(authority.principal.clone(), json!(person.subject));
        }
        if product == Product::Casework {
            let principal = &input.casework_principals[&grant.profile];
            if principal != "sub" {
                claims.insert(principal.clone(), json!(person.subject));
            }
        }
        if let Some(alias) = browser_alias {
            ensure!(
                !claims.contains_key("registry_scopes"),
                "browser scopes are supplied by the selected grant"
            );
            claims.insert("registry_principal".to_owned(), json!(person.subject));
            claims.insert("registry_scopes".to_owned(), json!(&scope_value));
            claims.insert(
                "name".to_owned(),
                json!(person.display_name.as_deref().unwrap_or(alias)),
            );
        }
        claims.extend([
            ("iss".to_owned(), json!(plan.issuer)),
            ("aud".to_owned(), audience),
            ("sub".to_owned(), json!(person.subject)),
            ("client_id".to_owned(), json!(client_id)),
            ("scope".to_owned(), json!(scope_value)),
            ("iat".to_owned(), json!(now)),
            ("exp".to_owned(), json!(expires)),
            ("jti".to_owned(), json!(uuid::Uuid::new_v4())),
        ]);
        let header = json!({"typ": "at+jwt"});
        let bytes = serde_json::to_vec(&Value::Object(claims))?;
        let token = sign_compact_jws(
            header.as_object().expect("header object").clone(),
            &bytes,
            &self.signer,
        )
        .await?;
        Ok(Zeroizing::new(token))
    }

    #[cfg(test)]
    pub(super) fn id_token(
        &self,
        issuer: &str,
        client_id: &str,
        subject: &str,
        nonce: &str,
        run_expires: u64,
    ) -> Result<Zeroizing<String>> {
        self.runtime
            .block_on(self.sign_id_token(issuer, client_id, subject, nonce, run_expires))
    }

    pub(super) async fn sign_id_token(
        &self,
        issuer: &str,
        client_id: &str,
        subject: &str,
        nonce: &str,
        run_expires: u64,
    ) -> Result<Zeroizing<String>> {
        let now = clock()?;
        let expires = run_expires.min(now.saturating_add(BROWSER_TOKEN_LIFETIME_SECONDS));
        ensure!(expires > now, "the development run has expired");
        let claims = json!({
            "iss": issuer, "aud": client_id, "sub": subject,
            "nonce": nonce, "iat": now, "exp": expires,
        });
        let header = json!({"typ": "JWT"});
        let token = sign_compact_jws(
            header.as_object().expect("header object").clone(),
            &serde_json::to_vec(&claims)?,
            &self.signer,
        )
        .await?;
        Ok(Zeroizing::new(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    fn payload(token: &str) -> Value {
        let encoded = token.split('.').nth(1).expect("JWT payload");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
    }

    fn browser_input() -> RunInput {
        serde_json::from_value(json!({
            "run_id": "0123456789abcdef0123456789abcdef",
            "project": "/project",
            "ttl_seconds": 1800,
            "plan": {
                "issuer": "http://127.0.0.1:45678",
                "products": [{"product": "breg", "project": ".", "audience": "registry-service"}],
                "people": {"person": {
                    "subject": "subject-1", "client": "cli-client",
                    "grants": {"breg": {"profile": "viewer", "scopes": ["registry.read"],
                        "claims": {"registry_actor_kind": "human", "role": "viewer"}}
                }}},
                "journey": {"id": "smoke", "steps": [{"id": "read", "product": "breg",
                    "as": "person", "method": "GET", "path": "/v1/records",
                    "expect": {"status": 200}}]}
            },
            "schema_people": [],
            "breg_authority": {"principal": "registry_principal", "purpose": false,
                "requires_postgis": false, "encrypts_fields": false, "named_clients": []},
            "casework_principals": {}, "binaries": {}
        }))
        .unwrap()
    }

    #[test]
    fn a_token_expires_five_minutes_after_issue_or_with_the_run() {
        assert_eq!(token_expiry(10_000, 1_000), 1_000 + TOKEN_LIFETIME_SECONDS);
        assert_eq!(token_expiry(1_100, 1_000), 1_100);
    }

    #[test]
    fn browser_access_token_uses_declared_client_and_one_resource() {
        let scratch = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(scratch.path()).unwrap();
        let input = browser_input();
        let token = issuer
            .browser_access_token(
                &input,
                "person",
                Product::Breg,
                "browser-client",
                &["registry.read".to_owned()],
                clock().unwrap() + 1800,
            )
            .unwrap();
        let claims = payload(&token);
        assert_eq!(claims["iss"], "http://127.0.0.1:45678");
        assert_eq!(claims["aud"], "registry-service");
        assert_eq!(claims["client_id"], "browser-client");
        assert_eq!(claims["registry_principal"], "subject-1");
        assert_eq!(claims["name"], "person");
        assert_eq!(claims["scope"], "registry.read");
        assert_eq!(claims["registry_scopes"], "registry.read");
        let cli = issuer
            .token(
                &input,
                &input.plan.people["person"],
                Product::Breg,
                clock().unwrap() + TOKEN_LIFETIME_SECONDS,
            )
            .unwrap();
        assert!(payload(&cli).get("registry_scopes").is_none());
    }

    #[test]
    fn id_token_binds_client_subject_and_nonce() {
        let scratch = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(scratch.path()).unwrap();
        let input = browser_input();
        let token = issuer
            .id_token(
                &input.plan.issuer,
                "browser-client",
                "subject-1",
                "nonce-1",
                clock().unwrap() + 1800,
            )
            .unwrap();
        let claims = payload(&token);
        assert_eq!(claims["iss"], input.plan.issuer);
        assert_eq!(claims["aud"], "browser-client");
        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["nonce"], "nonce-1");
    }

    #[test]
    fn browser_tokens_are_capped_by_run_expiry_and_browser_lifetime() {
        let scratch = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(scratch.path()).unwrap();
        let input = browser_input();
        let near_expiry = clock().unwrap() + 30;
        let access = issuer
            .browser_access_token(
                &input,
                "person",
                Product::Breg,
                "browser-client",
                &["registry.read".to_owned()],
                near_expiry,
            )
            .unwrap();
        let identity = issuer
            .id_token(
                &input.plan.issuer,
                "browser-client",
                "subject-1",
                "nonce-1",
                near_expiry,
            )
            .unwrap();
        assert_eq!(payload(&access)["exp"], near_expiry);
        assert_eq!(payload(&identity)["exp"], near_expiry);

        let distant_expiry = clock().unwrap() + 3600;
        let access = issuer
            .browser_access_token(
                &input,
                "person",
                Product::Breg,
                "browser-client",
                &["registry.read".to_owned()],
                distant_expiry,
            )
            .unwrap();
        let claims = payload(&access);
        let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
        assert_eq!(lifetime, BROWSER_TOKEN_LIFETIME_SECONDS);
    }
}
