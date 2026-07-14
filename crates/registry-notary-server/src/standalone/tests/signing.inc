    // SPDX-License-Identifier: Apache-2.0

    #[derive(Debug)]
    struct TestReadinessProvider {
        signer: LocalJwkSigner,
        readiness: Arc<AtomicU8>,
    }

    #[async_trait]
    impl SigningProvider for TestReadinessProvider {
        fn algorithm(&self) -> registry_platform_crypto::SigningAlgorithm {
            self.signer.algorithm()
        }

        fn key_id(&self) -> &str {
            self.signer.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.signer.public_jwk()
        }

        fn readiness(&self) -> KeyReadiness {
            key_readiness_from_u8(self.readiness.load(Ordering::SeqCst))
        }

        async fn sign(
            &self,
            payload: &[u8],
        ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
            self.signer.sign(payload).await
        }
    }

    #[test]
    fn signer_readiness_tracks_status_by_kid_and_counts_required_keys() {
        let provider_readiness =
            Arc::new(AtomicU8::new(key_readiness_to_u8(KeyReadiness::NotReady)));
        let provider: Arc<dyn SigningProvider> = Arc::new(TestReadinessProvider {
            signer: LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("jwk"))
                .expect("local signer builds"),
            readiness: Arc::clone(&provider_readiness),
        });
        let readiness = SignerReadiness::from_entries(vec![
            static_key_readiness(
                "did:web:notary.example#local".to_string(),
                SigningKeyProviderConfig::LocalJwkEnv,
                true,
                KeyReadiness::Ready,
            ),
            provider_key_readiness(
                "did:web:notary.example#hsm".to_string(),
                SigningKeyProviderConfig::Pkcs11,
                true,
                Arc::clone(&provider),
            ),
            static_key_readiness(
                "did:web:notary.example#publish-only".to_string(),
                SigningKeyProviderConfig::LocalJwkEnv,
                false,
                KeyReadiness::Ready,
            ),
        ]);

        assert_eq!(readiness.total(), 2);
        assert_eq!(readiness.ready_count(), 1);
        assert_eq!(readiness.failed_count(), 1);
        assert_eq!(
            readiness.provider_counts(),
            BTreeMap::from([("local_jwk_env".to_string(), 1), ("pkcs11".to_string(), 1)])
        );
        let by_kid = readiness
            .by_kid()
            .into_iter()
            .map(|entry| (entry.kid, entry.readiness))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_kid["did:web:notary.example#local"], KeyReadiness::Ready);
        assert_eq!(by_kid["did:web:notary.example#hsm"], KeyReadiness::NotReady);
        assert_eq!(
            by_kid["did:web:notary.example#publish-only"],
            KeyReadiness::Ready
        );

        provider_readiness.store(key_readiness_to_u8(KeyReadiness::Ready), Ordering::SeqCst);
        assert!(readiness.is_ready());
        assert_eq!(readiness.ready_count(), 2);
    }
    fn file_watch_key(path: &std::path::Path) -> SigningKeyConfig {
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::FileWatch,
            alg: "EdDSA".to_string(),
            kid: "did:web:issuer.example#file-watch".to_string(),
            status: registry_notary_core::SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: String::new(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: path.to_string_lossy().into_owned(),
            password_env: String::new(),
        }
    }

    fn test_file_modified(path: &std::path::Path) -> SystemTime {
        std::fs::metadata(path)
            .expect("test key metadata reads")
            .modified()
            .expect("test key modified time reads")
    }

    fn set_test_file_modified(path: &std::path::Path, modified: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("test key opens")
            .set_modified(modified)
            .expect("test key modified time sets");
        assert_eq!(
            test_file_modified(path),
            modified,
            "test filesystem preserved the requested modified time"
        );
    }

    fn bump_test_file_modified(path: &std::path::Path, previous: SystemTime) -> SystemTime {
        let modified = previous + Duration::from_secs(2);
        set_test_file_modified(path, modified);
        modified
    }

    async fn wait_for_file_watch_metadata_check() {
        tokio::time::sleep(FILE_WATCH_METADATA_CHECK_INTERVAL + Duration::from_millis(25)).await;
    }

    fn mark_file_watch_checked_now(provider: &FileWatchSigningProvider) {
        provider
            .file_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last_checked = Instant::now();
    }

    #[tokio::test]
    async fn file_watch_signing_key_reloads_valid_same_key_replacement_without_restart() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch signer test";

        let old_public = provider.public_jwk();
        let old_signature = provider.sign(payload).await.expect("old signer signs");
        verify(payload, &old_signature, &old_public).expect("old signature verifies");

        std::fs::write(&key_path, TEST_ISSUER_JWK_WITH_KID).expect("replacement key writes");
        wait_for_file_watch_metadata_check().await;
        let replacement_signature = provider
            .sign(payload)
            .await
            .expect("replacement signer signs");
        let replacement_public = provider.public_jwk();

        assert_eq!(old_signature, replacement_signature);
        assert_eq!(old_public, replacement_public);
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        verify(payload, &replacement_signature, &replacement_public)
            .expect("replacement signature verifies");
    }

    #[tokio::test]
    async fn file_watch_signing_key_debounces_metadata_checks_between_signatures() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch debounce";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        wait_for_file_watch_metadata_check().await;
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        mark_file_watch_checked_now(&provider);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        let immediate_signature = provider
            .sign(payload)
            .await
            .expect("debounced signer still signs");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Ready,
            "metadata is not checked again during the debounce interval"
        );
        verify(payload, &immediate_signature, &old_public)
            .expect("debounced signature still verifies with the last good key");

        wait_for_file_watch_metadata_check().await;
        let delayed_signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after refresh failure");
        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        verify(payload, &delayed_signature, &old_public)
            .expect("last good signature verifies after refresh failure");
    }

    #[test]
    fn file_watch_signing_key_missing_initial_file_fails_closed_without_path_leak() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("missing-issuer.jwk");
        let key = file_watch_key(&key_path);

        let err = FileWatchSigningProvider::from_config("file-watch", &key)
            .expect_err("missing watched key file fails startup");
        let err = err.to_string();

        assert!(err.contains("signing key 'file-watch' is invalid"));
        assert!(err.contains("file_watch key file could not be read"));
        let key_path_text = key_path.to_string_lossy();
        assert!(!err.contains(key_path_text.as_ref() as &str));
    }

    #[tokio::test]
    async fn file_watch_signing_key_keeps_last_good_signer_when_replacement_is_malformed() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch malformed replacement";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        set_test_file_modified(&key_path, initial_modified);
        let signature = provider
            .sign(payload)
            .await
            .expect("unchanged mtime keeps last good signer ready");
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public)
            .expect("unchanged-mtime malformed replacement was not reloaded");

        let malformed_modified = bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs");

        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public).expect("last good signature verifies");
        let debug = format!("{provider:?}");
        assert!(debug.contains("FileWatchSigningProvider"));
        let key_path_text = key_path.to_string_lossy();
        assert!(!debug.contains(key_path_text.as_ref() as &str));
        assert!(!debug.contains("2oPoxdKu"));

        std::fs::write(&key_path, TEST_ROTATED_ISSUER_JWK)
            .expect("wrong public-key replacement writes");
        bump_test_file_modified(&key_path, malformed_modified);
        wait_for_file_watch_metadata_check().await;
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after wrong-key replacement");
        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public).expect("wrong-key replacement was not swapped in");
    }

    #[tokio::test]
    async fn file_watch_signing_provider_reports_readiness_through_shared_trait() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let provider: Arc<dyn SigningProvider> = Arc::new(provider);

        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        provider
            .sign(b"registry-notary shared readiness")
            .await
            .expect("last good signer still signs");

        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
    }

    #[tokio::test]
    async fn file_watch_signing_key_readiness_is_reported_by_kid() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key_path_text = key_path.to_string_lossy();
        let evidence: EvidenceConfig = serde_norway::from_str(&format!(
            r#"
signing_keys:
  active-key:
    provider: file_watch
    path: "{key_path_text}"
    alg: EdDSA
    kid: did:web:issuer.example#file-watch
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#
        ))
        .expect("evidence config parses");
        let reuse_scoped_key_ids: HashSet<&str> = evidence
            .credential_profiles
            .values()
            .map(|profile| profile.signing_key.as_str())
            .collect();
        let registry = SigningKeyRegistry::from_config(&evidence, &reuse_scoped_key_ids)
            .expect("registry builds");
        let readiness = registry.signer_readiness();
        assert_eq!(
            readiness.by_kid()[0].readiness,
            KeyReadiness::Ready,
            "initial file-watch key is ready"
        );
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        let provider = registry
            .signing_provider("active-key")
            .expect("active provider exists");
        provider
            .sign(b"registry-notary readiness refresh")
            .await
            .expect("last good signer still signs");

        let by_kid = readiness
            .by_kid()
            .into_iter()
            .map(|entry| (entry.kid, entry.readiness))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_kid["did:web:issuer.example#file-watch"],
            KeyReadiness::Degraded
        );
    }

    #[tokio::test]
    async fn file_watch_signing_key_detects_same_mtime_content_change_after_debounce() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch same-mtime content detection";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        // Replace the file with same-key content but a different byte representation,
        // then restore mtime so it is identical to what was recorded at provider creation.
        std::fs::write(&key_path, TEST_ISSUER_JWK_WITH_KID).expect("same-key replacement writes");
        set_test_file_modified(&key_path, initial_modified);

        wait_for_file_watch_metadata_check().await;

        // After the debounce window, the content digest reveals the change even though
        // mtime is identical. The replacement is a valid same-public-key file, so
        // the provider should remain Ready with the refreshed signer.
        let signature = provider
            .sign(payload)
            .await
            .expect("provider signs after same-mtime reload");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Ready,
            "valid same-key same-mtime replacement keeps provider Ready"
        );
        assert_eq!(
            provider.public_jwk(),
            old_public,
            "public key is unchanged after same-key reload"
        );
        verify(payload, &signature, &old_public)
            .expect("signature from same-mtime refreshed signer verifies");
    }

    #[tokio::test]
    async fn file_watch_signing_key_detects_same_mtime_malformed_replacement_after_debounce() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch same-mtime malformed detection";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        // Replace with malformed content but restore mtime to the original value.
        std::fs::write(&key_path, "{ not valid jwk }").expect("malformed replacement writes");
        set_test_file_modified(&key_path, initial_modified);

        wait_for_file_watch_metadata_check().await;

        // After the debounce window the digest reveals the malformed replacement.
        // The provider must degrade but keep the last good signer.
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after same-mtime malformed replacement");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Degraded,
            "malformed same-mtime replacement degrades readiness after debounce"
        );
        assert_eq!(
            provider.public_jwk(),
            old_public,
            "last good public key is kept"
        );
        verify(payload, &signature, &old_public)
            .expect("last good signer signature verifies after same-mtime malformed replacement");
    }

    fn public_jwk_with_kid(public_jwk: &str, kid: &str) -> String {
        let mut value: Value = serde_json::from_str(public_jwk).expect("public JWK parses");
        value["kid"] = json!(kid);
        serde_json::to_string(&value).expect("public JWK serializes")
    }

    #[test]
    fn issuer_registry_uses_active_key_and_publishes_rotated_keys_once() {
        unsafe {
            std::env::set_var("TEST_ACTIVE_SIGNING_JWK", TEST_ISSUER_JWK);
            std::env::set_var("TEST_OLD_SIGNING_PUBLIC_JWK", TEST_OLD_ISSUER_PUBLIC_JWK);
            std::env::set_var(
                "TEST_EXPIRED_OLD_SIGNING_PUBLIC_JWK",
                public_jwk_with_kid(
                    TEST_OLD_ISSUER_PUBLIC_JWK,
                    "did:web:issuer.example#expired-old",
                ),
            );
            std::env::set_var("TEST_OLD_HSM_PUBLIC_JWK", TEST_OLD_HSM_PUBLIC_JWK);
            std::env::set_var("TEST_DISABLED_SIGNING_JWK", TEST_ISSUER_JWK);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_ACTIVE_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
  old-key:
    provider: local_jwk_env
    public_jwk_env: TEST_OLD_SIGNING_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#old
    status: publish_only
  old-hsm-key:
    provider: pkcs11
    public_jwk_env: TEST_OLD_HSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm-old
    status: publish_only
  expired-old-key:
    provider: local_jwk_env
    public_jwk_env: TEST_EXPIRED_OLD_SIGNING_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#expired-old
    status: publish_only
    publish_until_unix_seconds: 1
  disabled-key:
    provider: local_jwk_env
    private_jwk_env: TEST_DISABLED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#disabled
    status: disabled
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
"#,
        )
        .expect("evidence config parses");
        let registry = EvidenceIssuerRegistry::from_config(&evidence).expect("registry builds");

        assert!(registry.issuer("profile-a").is_ok());
        assert!(registry.issuer("profile-b").is_ok());
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 3);
        assert!(jwks.iter().all(|jwk| jwk.get("d").is_none()));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#active"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#old"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#hsm-old"));
        assert!(!jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#expired-old"));
        assert!(!jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#disabled"));
    }

    #[test]
    fn local_jwk_signing_key_rejects_mismatched_embedded_kid() {
        let jwk = r#"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#wrong","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
        unsafe {
            std::env::set_var("TEST_MISMATCHED_SIGNING_JWK", jwk);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_MISMATCHED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("mismatched key id must fail startup");
        assert!(
            err.to_string().contains("kid does not match"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn pkcs11_signing_key_fails_closed_when_feature_is_disabled() {
        unsafe {
            std::env::set_var(
                "TEST_PKCS11_PUBLIC_JWK",
                r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
            );
            std::env::set_var("TEST_PKCS11_PIN", "1234");
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: registry-notary
    pin_env: TEST_PKCS11_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_PKCS11_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("PKCS#11 must fail closed without feature");
        assert!(
            err.to_string().contains("provider 'pkcs11' is not enabled"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "pkcs11")]
    #[tokio::test]
    async fn pkcs11_signing_key_signs_with_softhsm_when_available() {
        let _guard = SOFTHSM_ENV_LOCK.lock().await;
        let Some(module_path) = softhsm_module_path() else {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but softhsm2-util is not available"
            );
            eprintln!("skipping SoftHSM signing test: softhsm2-util is not available");
            return;
        };
        if command_output(std::process::Command::new("openssl").arg("version")).is_none() {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but openssl is not available"
            );
            eprintln!("skipping SoftHSM signing test: openssl is not available");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let token_dir = tmp.path().join("tokens");
        std::fs::create_dir(&token_dir).expect("token dir is created");
        let softhsm_conf = tmp.path().join("softhsm2.conf");
        std::fs::write(
            &softhsm_conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                token_dir.display()
            ),
        )
        .expect("SoftHSM config is written");

        let token_label = format!("registry-notary-test-{}", std::process::id());
        let pin = "1234";
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", &softhsm_conf);
        }
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--init-token")
                .arg("--free")
                .arg("--label")
                .arg(&token_label)
                .arg("--so-pin")
                .arg("123456")
                .arg("--pin")
                .arg(pin),
        );

        let key_path = tmp.path().join("issuer-ed25519.pem");
        let secondary_key_path = tmp.path().join("issuer-ed25519-secondary.pem");
        run_command(
            std::process::Command::new("openssl")
                .arg("genpkey")
                .arg("-algorithm")
                .arg("ED25519")
                .arg("-out")
                .arg(&key_path),
        );
        run_command(
            std::process::Command::new("openssl")
                .arg("genpkey")
                .arg("-algorithm")
                .arg("ED25519")
                .arg("-out")
                .arg(&secondary_key_path),
        );
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--import")
                .arg(&key_path)
                .arg("--token")
                .arg(&token_label)
                .arg("--pin")
                .arg(pin)
                .arg("--label")
                .arg("issuer-signing-key")
                .arg("--id")
                .arg("01ab23cd")
                .arg("--force"),
        );
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--import")
                .arg(&secondary_key_path)
                .arg("--token")
                .arg(&token_label)
                .arg("--pin")
                .arg(pin)
                .arg("--label")
                .arg("issuer-signing-key-secondary")
                .arg("--id")
                .arg("02ab23cd")
                .arg("--force"),
        );

        let public_der = command_output(
            std::process::Command::new("openssl")
                .arg("pkey")
                .arg("-in")
                .arg(&key_path)
                .arg("-pubout")
                .arg("-outform")
                .arg("DER"),
        )
        .expect("openssl exports public key");
        assert!(
            public_der.len() >= 32,
            "Ed25519 SubjectPublicKeyInfo has key bytes"
        );
        let x = URL_SAFE_NO_PAD.encode(&public_der[public_der.len() - 32..]);
        let secondary_public_der = command_output(
            std::process::Command::new("openssl")
                .arg("pkey")
                .arg("-in")
                .arg(&secondary_key_path)
                .arg("-pubout")
                .arg("-outform")
                .arg("DER"),
        )
        .expect("openssl exports secondary public key");
        assert!(
            secondary_public_der.len() >= 32,
            "secondary Ed25519 SubjectPublicKeyInfo has key bytes"
        );
        let secondary_x =
            URL_SAFE_NO_PAD.encode(&secondary_public_der[secondary_public_der.len() - 32..]);
        let public_jwk_primary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm"
        })
        .to_string();
        let public_jwk_secondary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": secondary_x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm-secondary"
        })
        .to_string();
        unsafe {
            std::env::set_var("TEST_SOFTHSM_PIN", pin);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK", public_jwk_primary);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK_SECONDARY", public_jwk_secondary);
        }

        let evidence: EvidenceConfig = serde_norway::from_str(&format!(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#softhsm
    status: active
  hsm-key-secondary:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key-secondary
    key_id_hex: 02ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK_SECONDARY
    alg: EdDSA
    kid: did:web:issuer.example#softhsm-secondary
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
    holder_binding:
      mode: none
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key-secondary
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
    holder_binding:
      mode: none
"#,
        ))
        .expect("evidence config parses");

        let registry =
            EvidenceIssuerRegistry::from_config(&evidence).expect("SoftHSM signer builds");
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 2);
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm-secondary"));
        let issuer = registry
            .issuer("profile-a")
            .expect("profile-a issuer resolves");
        assert!(registry.issuer("profile-b").is_ok());
        let profile = evidence
            .credential_profiles
            .get("profile-a")
            .expect("profile-a exists");
        let results = vec![ClaimResultView {
            evaluation_id: "eval-softhsm".to_string(),
            claim_id: "claim-a".to_string(),
            claim_version: "1.0.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "person".to_string(),
                handle: "subject-ref".to_string(),
                identifier_schemes: vec!["registry-subject-ref".to_string()],
                profile: None,
            },
            value: Some(serde_json::json!({ "verified": true })),
            satisfied: Some(true),
            disclosure: "value".to_string(),
            redacted_fields: Vec::new(),
            format: registry_notary_core::FORMAT_CLAIM_RESULT_JSON.to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "softhsm-test".to_string(),
                "eval-test".to_string(),
                "claim".to_string(),
                "1".to_string(),
                registry_notary_core::ProvenanceUsed {
                    relay_consultation_count: 0,
                },
            ),
        }];
        let signed = registry_notary_core::sd_jwt::issue(
            profile,
            &issuer,
            &results,
            "subject-ref",
            None,
            time::OffsetDateTime::now_utc(),
            registry_notary_core::sd_jwt::IssueOptions::default(),
        )
        .await
        .expect("SoftHSM-backed credential issues");
        assert!(
            signed.compact.contains('~'),
            "issued credential includes SD-JWT disclosure separators"
        );
    }

    #[cfg(feature = "pkcs11")]
    fn softhsm_module_path() -> Option<String> {
        if let Some(path) = command_output(
            std::process::Command::new("softhsm2-util")
                .arg("--show-config")
                .arg("default-pkcs11-lib"),
        )
        .and_then(|output| String::from_utf8(output).ok())
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty() && std::path::Path::new(path).is_absolute())
        {
            return Some(path);
        }

        [
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
            "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .map(str::to_string)
    }

    #[cfg(feature = "pkcs11")]
    fn require_softhsm() -> bool {
        std::env::var("REGISTRY_NOTARY_REQUIRE_SOFTHSM")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    #[cfg(feature = "pkcs11")]
    fn command_output(command: &mut std::process::Command) -> Option<Vec<u8>> {
        let output = command.output().ok()?;
        output.status.success().then_some(output.stdout)
    }

    #[cfg(feature = "pkcs11")]
    fn run_command(command: &mut std::process::Command) {
        let output = command.output().expect("command starts");
        assert!(
            output.status.success(),
            "command failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
