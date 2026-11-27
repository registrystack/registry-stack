// SPDX-License-Identifier: Apache-2.0

//! `ActorKind::ALL` lists every actor kind.

use registry_documents_core::ActorKind;

/// An exhaustive match: a new kind fails to compile here until it is handled,
/// which is the reminder to list it in `ActorKind::ALL`.
fn listed(kind: ActorKind) -> bool {
    match kind {
        ActorKind::Service | ActorKind::Human => ActorKind::ALL.contains(&kind),
    }
}

#[test]
fn every_actor_kind_is_listed_once() {
    assert!(listed(ActorKind::Service));
    assert!(listed(ActorKind::Human));
    assert_eq!(ActorKind::ALL.len(), 2);
}
