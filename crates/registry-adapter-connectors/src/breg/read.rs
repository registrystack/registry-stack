// SPDX-License-Identifier: Apache-2.0
//! The BReg read family (the delivery plan's N1).
//!
//! Reads carry no command key, so they are plain blocking methods on the
//! connected connector, not [`Operation`](crate::operation::Operation)
//! implementations. One method performs one explicitly initiated exchange,
//! except [`RouteReads::list_page`], which advances the destination's own
//! continuation at most until the caller's item bound. The destination's
//! `lookup.unresolved` problem passes through unchanged as
//! [`Lookup::Unresolved`]: it is never retried and never read as
//! not-found.

use registry_breg_client::{
    BRegComplete, BRegContinuationProjection, BRegListRequest, BRegLookupRequest, BRegProposal,
    BRegProposalQuery, BRegProposalState, BRegProposalTurn, BRegRawDocument, BRegRecordOptions,
    BaseRegistryClientError, RegistryRecord, RegistryRecordSingleResponse,
};

use crate::operation::ConnectorFault;

use super::fault;

/// The reads one connected connector offers, bound to its route and
/// profile.
pub struct RouteReads<'a> {
    pub(crate) connector: &'a super::BregConnector,
}

/// One resolved or unresolved lookup. `Unresolved` is the destination's
/// typed `lookup.unresolved` answer (status 404, problem kind), not a
/// not-found answer and never a retry candidate.
#[derive(Debug)]
pub enum Lookup {
    /// Exactly one record resolved.
    Resolved(Box<BRegComplete<RegistryRecordSingleResponse>>),
    /// The destination's `lookup.unresolved` problem, passed through.
    Unresolved,
}

/// One bounded record list page: the items read and the persistable
/// continuation when the collection has more.
#[derive(Debug)]
pub struct RecordPage {
    /// The records across the pages this read advanced through.
    pub items: Vec<RegistryRecord>,
    /// The opaque, persistable continuation when the collection has more
    /// than the caller's bound admitted.
    pub continuation: Option<BRegContinuationProjection>,
}

/// The value-free summary of one listed Proposal: identity, lifecycle
/// state, turn, and submission version, and nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalSummary {
    /// The Proposal identifier.
    pub id: String,
    /// The Proposal lifecycle state (`draft`, `submitted`, `applied`,
    /// `cancelled`, `rejected`).
    pub state: BRegProposalState,
    /// Who the destination expects to act next, when derived.
    pub turn: Option<BRegProposalTurn>,
    /// The frozen submission version.
    pub submission_version: u32,
}

/// One bounded Proposal listing page.
#[derive(Debug)]
pub struct ProposalPage {
    /// The value-free summaries on this page.
    pub summaries: Vec<ProposalSummary>,
    /// The cursor when the collection has more; pass it back in the next
    /// query's `cursor`.
    pub next_cursor: Option<String>,
}

impl RouteReads<'_> {
    fn run<T: Send>(
        &self,
        exchange: impl std::future::Future<Output = Result<T, BaseRegistryClientError>> + Send,
    ) -> Result<T, ConnectorFault> {
        self.connector
            .block(exchange)
            .map_err(|error| fault(&error))
    }

    /// Read one record by identifier.
    pub fn get_record(
        &self,
        record_identifier: &str,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, ConnectorFault> {
        self.run(self.connector.client().get_record(
            self.connector.route(),
            record_identifier,
            &options(self.connector.profile()),
        ))
    }

    /// Read the newest retained revisions of one record as inert bytes.
    pub fn record_revisions(
        &self,
        record_identifier: &str,
    ) -> Result<BRegComplete<BRegRawDocument>, ConnectorFault> {
        self.run(self.connector.client().record_revisions(
            self.connector.route(),
            record_identifier,
            Some(self.connector.profile()),
        ))
    }

    /// Read one exact retained revision as inert bytes.
    pub fn get_record_revision(
        &self,
        record_identifier: &str,
        revision: u64,
    ) -> Result<BRegComplete<BRegRawDocument>, ConnectorFault> {
        self.run(self.connector.client().get_record_revision(
            self.connector.route(),
            record_identifier,
            revision,
            &options(self.connector.profile()),
        ))
    }

    /// Read the first record page and advance the destination's own
    /// continuation until at least `maximum_items` items are read, the
    /// collection ends, or the continuation stops. The caller's bound is
    /// the only automatic advance; a page that overshoots the bound keeps
    /// every item it returned.
    pub fn list_page(
        &self,
        request: &BRegListRequest,
        maximum_items: usize,
    ) -> Result<RecordPage, ConnectorFault> {
        let first = self.run(
            self.connector
                .client()
                .list_records(self.connector.route(), request),
        )?;
        let mut items = first.value.value.items;
        let mut continuation = first.value.continuation;
        while items.len() < maximum_items {
            let Some(next) = continuation.take() else {
                break;
            };
            let page = self.run(self.connector.client().continue_list(&next))?;
            items.extend(page.value.value.items);
            continuation = page.value.continuation;
        }
        Ok(RecordPage {
            items,
            continuation: continuation.map(|value| value.projection()),
        })
    }

    /// Evaluate one compiled selector against the request-origin values.
    /// The unresolved answer is [`Lookup::Unresolved`], the destination's
    /// own typed problem: never retried, never not-found.
    pub fn lookup(&self, request: &BRegLookupRequest) -> Result<Lookup, ConnectorFault> {
        match self.run(
            self.connector
                .client()
                .lookup_record(self.connector.route(), request),
        ) {
            Ok(record) => Ok(Lookup::Resolved(Box::new(record))),
            Err(ConnectorFault::Native { code: Some(code) })
                if code == super::problems::LOOKUP_UNRESOLVED =>
            {
                Ok(Lookup::Unresolved)
            }
            Err(error) => Err(error),
        }
    }

    /// Read one Proposal's value-free summary: the identity, state,
    /// turn, and submission version a submit attempt is prepared from.
    pub fn proposal_summary(&self, id: &str) -> Result<ProposalSummary, ConnectorFault> {
        let read = self.run(
            self.connector
                .client()
                .get_proposal(self.connector.proposal_get_binding()?, id),
        )?;
        let proposal = read.value;
        Ok(ProposalSummary {
            id: proposal.id().to_owned(),
            state: proposal.state(),
            turn: proposal.turn(),
            submission_version: proposal.submission_version(),
        })
    }

    /// List Proposals through the server's own filters and cursor. One
    /// bounded page; the runner advances by passing `next_cursor` back in
    /// the query.
    pub fn list_proposals_page(
        &self,
        query: &BRegProposalQuery,
    ) -> Result<ProposalPage, ConnectorFault> {
        let page = self.run(
            self.connector
                .client()
                .list_proposals(self.connector.proposal_collection()?, query),
        )?;
        Ok(ProposalPage {
            summaries: page
                .value
                .items
                .iter()
                .map(|proposal: &BRegProposal| ProposalSummary {
                    id: proposal.id().to_owned(),
                    state: proposal.state(),
                    turn: proposal.turn(),
                    submission_version: proposal.submission_version(),
                })
                .collect(),
            next_cursor: page.value.next_cursor,
        })
    }
}

fn options(profile: &str) -> BRegRecordOptions {
    BRegRecordOptions::default()
        .access_profile(profile)
        .expect("the connector's profile passed the client's validation at construction")
}
