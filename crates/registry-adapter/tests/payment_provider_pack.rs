// SPDX-License-Identifier: Apache-2.0
use registry_adapter::payments::pack::{PaymentProviderPack, ProviderPackPin};

const PACK: &str = "apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1\nkind: AdapterPaymentProviderPack\nid: payment-simulator\nversion: '1'\nconnector: simulator-p2g/v1\ncapabilities: [collection]\n";

#[test]
fn a_payment_connection_pins_the_exact_provider_pack() {
    let pack = PaymentProviderPack::from_yaml(PACK.as_bytes()).unwrap();
    let pin = ProviderPackPin {
        id: "payment-simulator".into(),
        version: "1".into(),
        digest: registry_platform_config::sha256_uri(PACK.as_bytes()),
    };
    assert!(pack.check_pin(&pin, PACK.as_bytes()).is_ok());
    let changed = PACK.replace("simulator-p2g/v1", "mifos-ph-ee/v1");
    assert!(pack.check_pin(&pin, changed.as_bytes()).is_err());
}
