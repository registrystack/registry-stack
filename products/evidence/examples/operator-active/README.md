# Operator activity example

This independent EvidenceProject asks one fixed question: whether a source
operator is active for facility administration. Its HTTP Source yields private
`active`, `status`, and address-canary facts. The named derivation releases one
Boolean. An active flag with suspended status yields `false`.

Copy this directory and the sibling `standalone/` directory to a writable
workspace, preserving their relative paths. Follow the [standalone setup and
request journey](../standalone/README.md) from the operator copy, with these
substitutions:

- Generate `.generated/secrets/operator-source-token` as the source token.
- Start `../standalone/serve-source.py --port 8081 --token-file .generated/secrets/operator-source-token` from this project, using the source script's actual path in your copy.
- Register the `facility-service` access profile.
- Prepare `operator-active --client demo --purpose facility-administration --subject operator:operator-id=active --name operator`.
- Read request, authorization, response and verification files under `.evidence/requests/operator/`.

The same check, fixture, type, explain, dev, verification and package commands use
this project's `evidence.yaml`, `local-target.yaml`, and `dev-authority.yaml`.
Synthetic operator IDs `inactive` and `suspended` yield `false`; `missing` and
`ambiguous` are refused. The fixtures exercise both positive and false results,
source failures, output bounds and private-canary protection.

A public BReg HTTP endpoint can replace the synthetic source when its reviewed
Source contract and target connection are supplied. This integration uses that
endpoint's public contract and credentials. Evidence does not share its runtime,
database or write authority.
