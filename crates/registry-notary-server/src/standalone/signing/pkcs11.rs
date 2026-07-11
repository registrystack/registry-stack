// SPDX-License-Identifier: Apache-2.0
//! PKCS#11 signing provider implementation.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use registry_notary_core::SigningKeyConfig;
use registry_platform_crypto::{
    verify, KeyReadiness, PublicJwk, SigningAlgorithm, SigningError, SigningProvider,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::super::{invalid_signing_key, StandaloneServerError};

const SELF_TEST_PAYLOAD: &[u8] = b"registry-notary pkcs11 signing self-test";
const SIGN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(in crate::standalone) struct Pkcs11SigningProvider {
    key_id: String,
    public_jwk: PublicJwk,
    context: Arc<Pkcs11>,
    slot: Slot,
    pin: Arc<Zeroizing<String>>,
    session: Arc<std::sync::Mutex<Pkcs11SessionState>>,
    sign_permit: Arc<Semaphore>,
    ready: Arc<AtomicBool>,
    key_label: String,
    key_id_bytes: Vec<u8>,
}

struct Pkcs11SessionState {
    session: Session,
    private_key: ObjectHandle,
}

impl Pkcs11SigningProvider {
    pub(in crate::standalone) fn from_config(
        config_key_id: &str,
        config: &SigningKeyConfig,
    ) -> Result<Self, StandaloneServerError> {
        let public_raw = Zeroizing::new(read_required_env(
            config_key_id,
            &config.public_jwk_env,
            "public_jwk_env",
        )?);
        let public_jwk = PublicJwk::parse(public_raw.as_str()).map_err(|_| {
            invalid_signing_key(config_key_id, "public_jwk_env is not a valid public JWK")
        })?;
        if public_jwk.kid.as_deref() != Some(config.kid.as_str()) {
            return Err(invalid_signing_key(
                config_key_id,
                "public JWK kid does not match configured kid",
            ));
        }
        if public_jwk.alg.as_deref() != Some(config.alg.as_str()) {
            return Err(invalid_signing_key(
                config_key_id,
                "public JWK alg does not match configured alg",
            ));
        }

        let pin = Arc::new(Zeroizing::new(read_required_env(
            config_key_id,
            &config.pin_env,
            "pin_env",
        )?));
        let key_id_bytes = hex::decode(&config.key_id_hex)
            .map_err(|_| invalid_signing_key(config_key_id, "key_id_hex is not valid hex"))?;
        let context = Pkcs11::new(&config.module_path)
            .map_err(|_| invalid_signing_key(config_key_id, "could not load PKCS#11 module"))?;
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(_) => {
                return Err(invalid_signing_key(
                    config_key_id,
                    "could not initialize PKCS#11 module",
                ));
            }
        }
        let slot = find_token_slot(&context, config_key_id, &config.token_label)?;
        ensure_eddsa_mechanism(&context, slot, config_key_id)?;
        let session = open_logged_in_session(&context, slot, &pin, config_key_id)?;
        let private_key =
            find_private_key(&session, &config.key_label, &key_id_bytes, config_key_id)?;

        let provider = Self {
            key_id: config.kid.clone(),
            public_jwk,
            context: Arc::new(context),
            slot,
            pin,
            session: Arc::new(std::sync::Mutex::new(Pkcs11SessionState {
                session,
                private_key,
            })),
            sign_permit: Arc::new(Semaphore::new(1)),
            ready: Arc::new(AtomicBool::new(true)),
            key_label: config.key_label.clone(),
            key_id_bytes,
        };
        provider.self_test(config_key_id)?;
        Ok(provider)
    }

    fn self_test(&self, config_key_id: &str) -> Result<(), StandaloneServerError> {
        let provider = self.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(provider.sign_sync(SELF_TEST_PAYLOAD));
        });
        let signature = rx
            .recv_timeout(SIGN_TIMEOUT)
            .map_err(|_| {
                self.mark_unhealthy();
                invalid_signing_key(config_key_id, "PKCS#11 signer self-test timed out")
            })?
            .map_err(|_| invalid_signing_key(config_key_id, "PKCS#11 signer self-test failed"))?;
        verify(SELF_TEST_PAYLOAD, &signature, &self.public_jwk).map_err(|_| {
            invalid_signing_key(
                config_key_id,
                "PKCS#11 signer self-test verification failed",
            )
        })
    }

    fn mark_unhealthy(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }

    fn sign_sync(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        if let Ok(signature) = self.sign_with_current_session(payload) {
            return Ok(signature);
        }

        tracing::warn!(
            provider = "pkcs11",
            key_id = %self.key_id,
            "PKCS#11 sign failed with current session; reopening session"
        );
        let session = open_logged_in_session_for_signing(&self.context, self.slot, &self.pin)?;
        let private_key =
            find_private_key_for_signing(&session, &self.key_label, &self.key_id_bytes)?;
        {
            let mut state = self
                .session
                .lock()
                .map_err(|_| SigningError::external("PKCS#11 session lock poisoned"))?;
            state.session = session;
            state.private_key = private_key;
        }
        let result = self.sign_with_current_session(payload);
        if result.is_ok() {
            tracing::info!(
                provider = "pkcs11",
                key_id = %self.key_id,
                "PKCS#11 sign succeeded after session reopen"
            );
        }
        result
    }

    fn sign_with_current_session(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        let session = self
            .session
            .lock()
            .map_err(|_| SigningError::external("PKCS#11 session lock poisoned"))?;
        let mechanism = eddsa_mechanism();
        session
            .session
            .sign(&mechanism, session.private_key, payload)
            .map_err(|_| SigningError::external("PKCS#11 sign failed"))
    }
}

impl fmt::Debug for Pkcs11SigningProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11SigningProvider")
            .field("kid", &self.key_id)
            .field("key_label", &self.key_label)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SigningProvider for Pkcs11SigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EdDsa
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        if !self.ready.load(Ordering::SeqCst) {
            tracing::warn!(
                provider = "pkcs11",
                key_id = %self.key_id,
                "PKCS#11 signer is unhealthy"
            );
            return Err(SigningError::external("PKCS#11 signer is unhealthy"));
        }
        let started_at = Instant::now();
        let permit = tokio::time::timeout(SIGN_TIMEOUT, self.sign_permit.clone().acquire_owned())
            .await
            .map_err(|_| {
                tracing::warn!(
                    provider = "pkcs11",
                    key_id = %self.key_id,
                    "PKCS#11 sign timed out while waiting for signing permit"
                );
                SigningError::external("PKCS#11 sign timed out")
            })?
            .map_err(|_| SigningError::external("PKCS#11 signing gate was closed"))?;
        let remaining = SIGN_TIMEOUT.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Err(SigningError::external("PKCS#11 sign timed out"));
        }
        let provider = self.clone();
        let payload = payload.to_vec();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            provider.sign_sync(&payload)
        });
        let result = tokio::time::timeout(remaining, task)
            .await
            .map_err(|_| {
                self.mark_unhealthy();
                tracing::error!(
                    provider = "pkcs11",
                    key_id = %self.key_id,
                    "PKCS#11 sign timed out and signer was marked unhealthy"
                );
                SigningError::external("PKCS#11 sign timed out")
            })?
            .map_err(|_| SigningError::external("PKCS#11 sign task failed"))?;
        match &result {
            Ok(_) => tracing::debug!(
                provider = "pkcs11",
                key_id = %self.key_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "PKCS#11 sign succeeded"
            ),
            Err(_) => tracing::warn!(
                provider = "pkcs11",
                key_id = %self.key_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "PKCS#11 sign failed"
            ),
        }
        result
    }

    fn readiness(&self) -> KeyReadiness {
        if self.ready.load(Ordering::SeqCst) {
            KeyReadiness::Ready
        } else {
            KeyReadiness::NotReady
        }
    }
}

fn read_required_env(
    config_key_id: &str,
    env_name: &str,
    field: &str,
) -> Result<String, StandaloneServerError> {
    std::env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_signing_key(config_key_id, &format!("{field} is missing or empty")))
}

fn find_token_slot(
    context: &Pkcs11,
    config_key_id: &str,
    token_label: &str,
) -> Result<Slot, StandaloneServerError> {
    let matches = context
        .get_slots_with_token()
        .map_err(|_| invalid_signing_key(config_key_id, "could not list PKCS#11 slots"))?
        .into_iter()
        .filter(|slot| {
            context
                .get_token_info(*slot)
                .map(|info| info.label().trim() == token_label)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [slot] => Ok(*slot),
        [] => Err(invalid_signing_key(
            config_key_id,
            "PKCS#11 token was not found",
        )),
        _ => Err(invalid_signing_key(
            config_key_id,
            "multiple PKCS#11 tokens matched token_label",
        )),
    }
}

fn ensure_eddsa_mechanism(
    context: &Pkcs11,
    slot: Slot,
    config_key_id: &str,
) -> Result<(), StandaloneServerError> {
    let supported = context
        .get_mechanism_list(slot)
        .map_err(|_| invalid_signing_key(config_key_id, "could not list PKCS#11 mechanisms"))?;
    if supported.contains(&MechanismType::EDDSA) {
        Ok(())
    } else {
        Err(invalid_signing_key(
            config_key_id,
            "PKCS#11 token does not support CKM_EDDSA",
        ))
    }
}

fn open_logged_in_session(
    context: &Pkcs11,
    slot: Slot,
    pin: &Zeroizing<String>,
    config_key_id: &str,
) -> Result<Session, StandaloneServerError> {
    let session = context
        .open_ro_session(slot)
        .map_err(|_| invalid_signing_key(config_key_id, "PKCS#11 session open failed"))?;
    let auth_pin = AuthPin::new(pin.as_str().to_string().into_boxed_str());
    match session.login(UserType::User, Some(&auth_pin)) {
        Ok(()) => Ok(session),
        Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
        Err(_) => Err(invalid_signing_key(config_key_id, "PKCS#11 login failed")),
    }
}

fn find_private_key(
    session: &Session,
    key_label: &str,
    key_id_bytes: &[u8],
    config_key_id: &str,
) -> Result<ObjectHandle, StandaloneServerError> {
    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Id(key_id_bytes.to_vec()),
    ];
    let matches = session
        .find_objects(&template)
        .map_err(|_| invalid_signing_key(config_key_id, "PKCS#11 private-key lookup failed"))?;
    match matches.as_slice() {
        [handle] => Ok(*handle),
        [] => Err(invalid_signing_key(
            config_key_id,
            "PKCS#11 private key was not found",
        )),
        _ => Err(invalid_signing_key(
            config_key_id,
            "multiple PKCS#11 private keys matched lookup",
        )),
    }
}

fn open_logged_in_session_for_signing(
    context: &Pkcs11,
    slot: Slot,
    pin: &Zeroizing<String>,
) -> Result<Session, SigningError> {
    let session = context
        .open_ro_session(slot)
        .map_err(|_| SigningError::external("PKCS#11 session open failed"))?;
    let auth_pin = AuthPin::new(pin.as_str().to_string().into_boxed_str());
    match session.login(UserType::User, Some(&auth_pin)) {
        Ok(()) => Ok(session),
        Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
        Err(_) => Err(SigningError::external("PKCS#11 login failed")),
    }
}

fn find_private_key_for_signing(
    session: &Session,
    key_label: &str,
    key_id_bytes: &[u8],
) -> Result<ObjectHandle, SigningError> {
    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Id(key_id_bytes.to_vec()),
    ];
    let matches = session
        .find_objects(&template)
        .map_err(|_| SigningError::external("PKCS#11 private-key lookup failed"))?;
    match matches.as_slice() {
        [handle] => Ok(*handle),
        [] => Err(SigningError::external("PKCS#11 private key was not found")),
        _ => Err(SigningError::external(
            "multiple PKCS#11 private keys matched lookup",
        )),
    }
}

fn eddsa_mechanism() -> Mechanism<'static> {
    Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519))
}
