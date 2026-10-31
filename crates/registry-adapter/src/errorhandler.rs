// SPDX-License-Identifier: Apache-2.0

//! The error handler: Camel's error handler, redelivery policy, and
//! exception clauses over a closed hierarchy of error classes
//! (`products/adapter/CONCEPT.md` section 8.7).
//!
//! Matching is Camel's: the clause whose class is closest to the error
//! or any of its causes wins, ties going to the most deeply nested
//! cause; a clause never matches a class above its own, and `onWhen`
//! narrows a clause. `errorHandler` is `defaultErrorHandler` (no
//! redelivery, the error propagates to the caller) or `noErrorHandler`;
//! the journal is the fixed dead letter, and every exhausted exchange is
//! journaled. Redelivery options: `maximumRedeliveries` (default 0),
//! `retryDelaySeconds` (default 1 s), `useExponentialBackOff` with
//! `backOffMultiplier` (default 2), `maximumRetryDelaySeconds` (default
//! 60 s), and collision avoidance. `retryWhile` sits on the clause and
//! the default handler, as in Camel, and only stops redelivery earlier.
//! Redelivery is per failing endpoint send and
//! reaches upstream component sends only, never a `to: direct:` send.
//! `onException` clauses carry `exception`, `onWhen`, `handled`,
//! `continued`, `retryWhile`, redelivery options, and nested steps; an
//! error raised inside a clause is not handled again and becomes the
//! exchange's failure.
//!
//! The uncatchable, terminal, journaled classes (`budget.exhausted`,
//! `credential.rejected`, `disclosure.violation`, `egress.refused`,
//! `script.budget-exceeded`) fire no clause at all, and the facade
//! classes the `rest` consumer raises outside any route exist so the
//! profile maps every response a caller receives into its shape
//! (section 8.11.6).
