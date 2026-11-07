#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use registry_platform_crypto::jwe::{
    decrypt_compact_ecdh_es, EcdhEsP256Key, JweEnc, JweLimits,
};

fn key() -> &'static EcdhEsP256Key {
    static KEY: OnceLock<EcdhEsP256Key> = OnceLock::new();
    KEY.get_or_init(|| EcdhEsP256Key::from_private_scalar(&[0x11; 32], "fuzz").expect("fixed key"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let _ = decrypt_compact_ecdh_es(
        token,
        key(),
        &[JweEnc::A128Gcm, JweEnc::A256Gcm],
        &JweLimits::default(),
    );
});
