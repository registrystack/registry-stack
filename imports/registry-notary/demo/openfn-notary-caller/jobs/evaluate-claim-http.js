// SPDX-License-Identifier: Apache-2.0
//
// OpenFn workflow template for a Registry Notary evaluation gate.
//
// Expected secrets/configuration:
//   state.configuration.notary_base_url
//   state.configuration.notary_token
//   state.configuration.notary_target_fingerprint_key
//
// This template intentionally does not use @openfn/language-http for the
// Notary call. In @openfn/language-http@7.3.1, non-2xx responses can log the
// response body before workflow code can redact Problem Details `detail`.

import { execute, fn } from "@openfn/language-common";
import {
  callNotaryEvaluation,
} from "../src/index.js";

const evaluationOptions = {
  claimId: "benefits-person-exists",
  purpose: "benefits_eligibility",
  disclosure: "predicate",
  relationship: { type: "self" },
  target: {
    type: "Person",
    identifiers: [
      {
        scheme: "national_id",
        valueFrom: "national_id",
        issuer: "civil_registry",
      },
    ],
  },
};

execute(
  fn((state) => callNotaryEvaluation(state, evaluationOptions)),
);
