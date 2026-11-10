// SPDX-License-Identifier: Apache-2.0
//! Local access-token issuer. Signing is available only to the owner through the CLI.

use anyhow::{ensure, Context, Result};
use registry_platform_crypto::{
    generate_private_jwk, jws::sign_compact_jws, GeneratedKeyAlgorithm, LocalJwkSigner, PrivateJwk,
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use zeroize::Zeroizing;

use super::{
    clock,
    plan::{self, Product, TestPerson},
    write_private, RunInput,
};

pub(super) struct Issuer {
    signer: LocalJwkSigner,
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
        Ok(Self {
            signer: LocalJwkSigner::new(key)?,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        })
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
        let now = clock()?;
        let expires = expires.min(now + Duration::from_secs(300).as_secs());
        ensure!(expires > now, "the development run has expired");
        let plan = &input.plan;
        let grant = &person.grants[&product];
        let forward_context = product == Product::Casework && person.casework_context;
        let mut claims = grant.claims.clone();
        let scopes = grant
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
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
        claims.extend([
            ("iss".to_owned(), json!(plan.issuer)),
            ("aud".to_owned(), audience),
            ("sub".to_owned(), json!(person.subject)),
            ("client_id".to_owned(), json!(person.client)),
            (
                "scope".to_owned(),
                json!(scopes.into_iter().collect::<Vec<_>>().join(" ")),
            ),
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
}
