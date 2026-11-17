// SPDX-License-Identifier: Apache-2.0

//! The `throwException` processor: `exceptionType` names a catchable error class,
//! typically an `outcome.*` class, and `message` is an
//! optional constant, bounded, which fills the profile's
//! `problemDetail` slot when the problem's envelope has one.
//!
//! Raised inside a route it is handled by the route's clauses like any
//! error; raised inside an `onException` clause it is the exchange's
//! final failure. A pack never writes a problem body and never names a
//! profile's problem code: the profile decides what the caller sees.
