// SPDX-License-Identifier: Apache-2.0
use registry_adapter::payments::registry::{BillState, BillView};
use serde_json::json;

#[test]
fn bill_projection_keeps_domain_version_and_exact_money() {
    let id = uuid::Uuid::new_v4();
    let data = json!({"billVersion":7,"billDigest":"a".repeat(64),"institutionId":"ministry","serviceId":"permit",
        "requestId":"req1","payerId":"payer1","payerFinancialAddress":"synthetic-payer",
        "tariffId":"permit-v1","tariffVersion":1,"tariffDigest":"b".repeat(64),
        "amountMinor":9007199254740991_u64,"currency":"USD","currencyScale":2,"simulation":true,"paymentState":"due-unbound"});
    let bill = BillView::decode(id, serde_json::from_value(data.clone()).unwrap()).unwrap();
    assert_eq!(bill.snapshot.bill_version, 7);
    assert_eq!(bill.snapshot.money.value, "90071992547409.91");
    assert_eq!(bill.state, BillState::DueUnbound);
    for field in ["billVersion", "amountMinor", "currencyScale"] {
        let mut changed = data.clone();
        changed[field] = json!(1.5);
        assert!(BillView::decode(id, serde_json::from_value(changed).unwrap()).is_err());
    }
    let mut malformed = data;
    malformed["paymentAttemptId"] = json!("not-a-uuid");
    assert!(BillView::decode(id, serde_json::from_value(malformed).unwrap()).is_err());
}
