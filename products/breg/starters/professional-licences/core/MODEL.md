# Professional licence core profile

This synthetic learning register records a regulator's dated authorization to
practise a profession. Recording a licence fact does not issue a credential,
verify a person's identity, award a qualification, establish a practice role,
or prove that a person may lawfully practise now. All supplied people,
regulators, jurisdictions, identifiers and codes are fictional.

## Exact mappings and local decisions

The pinned PublicSchema draft is commit
`1ea9ce333918693b29aec31068fac412e02cb8dc`. Its `government.yaml`
ProfessionalLicense specializes Authorization, which specializes Registration
in `registry.yaml`. This profile intentionally implements a small selection,
not the complete draft or a jurisdiction's licensing legislation.

| BReg field or entity | PublicSchema concept | Profile decision |
| --- | --- | --- |
| professional-license | ProfessionalLicense | One recorded professional authorization |
| localIdentifier | identifiers | Unique bounded local key, not a complete Identifier structure or a national licence number |
| personReference | registered_subject | Inert external instance URI expected to identify a person |
| regulatorReference | registration_authority | Inert external instance URI expected to identify the regulator |
| jurisdictionReference | registration_jurisdiction | Inert external instance URI expected to identify the relevant jurisdiction |
| professionCode | profession_code | Closed example vocabulary in an explicitly local scheme |
| validFrom | valid_from | Required first calendar date of the asserted authorization, not the date the record was entered |
| validTo | valid_to | Optional last calendar date; omission means unknown, not perpetual validity |
| practiceScope | authorization_conditions | Required bounded statement of scope or conditions, not a qualification or specialty record |
| licenceStatus | Local extension | Recorded status, not a computed current authorization decision |
| scope-correction | Local review workflow | Native typed record reference plus a proposed practice-scope value, reason and supporting reference |

The external reference fields are required bounded strings. BReg does not
validate their URI syntax, dereference them, check their existence or confirm
the referenced entity type. Adopters must resolve and validate identifiers
through their institutional process. These are a deliberate minimal projection
of the research model's qualified RegistryReference, not equivalent to its full
register/record/subject provenance structure. They never duplicate an external
person or regulator master. Class IRIs describe concepts, never instances.
No importer may infer identity by matching a person's name.

The local profession codes `example-nursing` and `example-engineering` and the
statuses `recorded-active`, `recorded-suspended` and `recorded-expired` are
explicit examples. They are not international classifications or jurisdictional
legal definitions. Status is recorded independently of dates; this profile
neither computes currentness from the clock nor claims to reconcile a status
with a period. Known date pairs enforce validFrom <= validTo, including equal
dates. Invalid calendar dates are refused. History records changes, not legal
renewal, revocation or effective-dated status transitions.

The earlier integrated research model also considered practitioner identities,
qualifications, specialties, practice roles, competence and disciplinary
records. Those are outside this core profile. No additional supporting record
is needed just to copy an external master. Correction requests provide the
one justified native relationship to the locally owned licence record.

## Fixed authority and privacy policy

All routes require authentication, a selected profile, its `starter:*` scope
and the `starter-learning` purpose. Browser previews grant no local authority.
`editor` is the example registrar role; identifiers retain that name to keep
the local learning clients consistent across starters.

| Actor | Licence records | Scope corrections |
| --- | --- | --- |
| Reader | Get/list profession, jurisdiction, recorded status and validity dates only | No access |
| Editor (registrar) | Create, get/list and inspect all-field history | Create/edit own draft, submit, revise or cancel own requests |
| Reviewer | Get/list and inspect all-field history | Inspect, approve, reject, request revision and manually apply |

Reader output omits the local identifier, person, regulator and practice scope.
It is a minimized non-personal field slice, not a promise of anonymity or a
public publication policy. The record UUID and permitted facts may still be
linkable. Reader has no history grant. Editor/reviewer history includes old
readable values. The Manifest projection describes the editor's model and
grants no runtime access.

These learning profiles have explicit registry-wide grants, with no jurisdiction
or ownership row restriction for licence records. Review requests use owner
visibility for editors. All omitted operations, including deletion and direct
licence PATCH, are denied. The controlled PATCH operation requires the authored
review path. The fixed effect changes only practiceScope: local identifier,
external references, profession, status and dates remain unchanged. A different
status or entitlement lifecycle needs its own reviewed institutional design.

A distinct principal must approve; acquiring the reviewer profile cannot let a
submitter approve their own request. Approval alone changes no licence.
The reviewer applies the exact frozen effect with the target's expected
revision. A stale target requires the native revision and review path.
Reasons and supporting references are restricted bounded text, not uploaded
proof, verified external evidence or authority to license someone.

## Examples and verification

`starter-data` creates three independent fictional licences with different
profession/status combinations. `first-record` needs no samples: its explicit
fictional external URIs permit an independent create and read. Edit
`examples/inputs/first-record.json` before the first run. Native retained state
binds exact inputs and captured UUIDs to each attempt. The correction's
`recordRef` is resolved to the captured first-record UUID by the native runner;
external URI strings remain unchanged and trigger no lookup.

The normal and security journey suites exercise independent creation,
submission, separate approval and application, rejection, unchanged unrelated
fields, local vocabulary refusal and date validation. The maintained real-router
starter test additionally checks missing grants, direct mutation refusal,
reader minimization and same-principal review refusal. Compiler checks establish
authoring validity; only an executed PostgreSQL test proves runtime behavior.

## Attribution and adoption

See `ATTRIBUTION.md`, `PUBLICSCHEMA-LICENSE.txt` and the pinned source metadata
in `starter-template.json`. PublicSchema concepts are adapted under CC BY 4.0.
The external-reference representation, fixed field selection, code schemes,
permissions, review policy and constraints are Registry Stack decisions.
This profile makes no PublicSchema endorsement, licensing-law compliance,
credential issuance or external identity-validation claim. Review these local
assumptions and authority boundaries before institutional adoption.
