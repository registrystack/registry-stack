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
| licensedActivities | Local extension | Required nonempty collection of distinct codes from the fictional generic activity catalogue |
| authorizationConditions | authorization_conditions | Bounded free-text conditions; the empty string means no conditions are recorded |
| licenceStatus | Local extension | Recorded status, not a computed current authorization decision |
| scope-correction | Local review workflow | Native typed record reference plus proposed activities and conditions, a reason and supporting reference |

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

| Actor | Licence records | Recorded-decision corrections |
| --- | --- | --- |
| Reader | Get/list profession, jurisdiction, recorded status and validity dates only | No access |
| Editor (registrar) | Create, get/list and inspect all-field history | List, create/edit own draft, submit, revise or cancel own requests |
| Reviewer | Get/list and inspect all-field history | List, inspect, approve, reject, request revision and manually apply |
| Holder | Get/list own licences through exact trusted person-reference equality | List, create/edit, submit, revise or cancel own corrections against currently owned licences |

Reader output omits the local identifier, person, regulator, activities and conditions.
It is a minimized non-personal field slice, not a promise of anonymity or a
public publication policy. The record UUID and permitted facts may still be
linkable. Reader has no history grant. Editor/reviewer history includes old
readable values. The Manifest projection describes the editor's model and
grants no runtime access.

Reader, editor and reviewer retain explicit registry-wide learning grants.
Holder reads require the verified scalar `person_reference` claim to equal the
licence `person-reference` field. Holder and editor request lists use owner
visibility; reviewer lists expose the authorized queue with native state filters.
All three licence lists support exact `localIdentifier` filtering. All omitted operations, including deletion and direct
licence PATCH, are denied. The controlled PATCH operation requires the authored
review path. The fixed effect atomically replaces only licensedActivities and authorizationConditions: local identifier,
external references, profession, status and dates remain unchanged. A different
status or entitlement lifecycle needs its own reviewed institutional design.

A distinct principal must approve; acquiring the reviewer profile cannot let a
submitter approve their own request. Approval alone changes no licence.
The reviewer applies the exact frozen effect with the target's expected
revision. A stale target requires the native revision and review path.
Reasons and supporting references are restricted bounded text, not uploaded
proof, verified external evidence or authority to license someone.

## Examples and verification

`starter-data` creates three independent fictional professional licences with different
profession/activity/status combinations. `first-record` needs no samples: its explicit
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

## Trusted holder linkage

An operator provisions each authenticated human's stable `registry_principal`
and scalar `person_reference` at the trusted issuer. The latter is the exact
inert person URI the registrar records on each licence, never an email or a
browser-selected identifier. A person can have several licences or none; a
mapped person with none receives an empty list. A missing or malformed mapping
grants no holder licence access. Operator enrollment must reject ambiguous or
duplicate human mappings; this register does not infer that linkage. Changing a
mapping requires trusted administration, and already issued tokens retain the
old value until their configured expiry. Live ownership transfer and immediate
identity revocation are not demonstrated here.

The holder request grant explicitly declares `submitterTargets:
[professional-license]`. The engine reuses the same selected profile's current
GET authority for that native reference on create, draft PATCH/retarget, submit,
revise/rebase and exact retry. Request ownership alone grants no target access.
An inaccessible target yields a value-free precondition refusal, while absent
claim authority conceals the operation. Owner request reads and cancellation
remain available after target access changes. Review context and retained target
links remain subject to current target authority.

This bounded Beta capability is for fixed native-reference effects with manual
application. Admission takes PostgreSQL SHARE locks on target tables until its
short request transaction commits, so concurrent target writes wait. Target
entities are ordered and cannot themselves be request entities. This favors a
small authority mechanism for institutional pilots over high-throughput write
concurrency; it is not a general row-level admission or delegation framework.

## Fictional activity catalogue and conditions

This reusable professional-licence template includes `example-nursing` and
`example-engineering` as coequal fictional profession codes. Its generic activity
catalogue contains `example-assessment` (assessment), `example-advisory-services`
(advisory services), and `example-practical-services` (practical services). These
are teaching labels applicable to either example profession, not clinical or
engineering scope standards, specialty taxonomies, competency assessments or
legal permissions. One licence can record one, two or all three distinct activities.

An adopter specializes a copy of this template for its particular profession
and institution before deployment. That adaptation can narrow the profession
vocabulary and replace the fictional activity catalogue, while preserving the
separate activity/conditions fields, complete replacement correction, and native
authority and review controls. A nursing-specific registry is one such adapted
consumer, not the generic template itself. Real permitted activities and their
professional applicability require an institution's reviewed governing rules;
this example catalogue does not encode those rules.

`licensedActivities` is a required JSON array of distinct catalogue strings, with
one to three entries and a 512-byte bound. The governed structured-field schema
rejects unknown codes, duplicates and empty arrays. Both example professions
use the same explicitly fictional activity catalogue. Unknown professions are
refused by the separate profession vocabulary.
`authorizationConditions` is a required wire string of at most 500 characters.
Its content is optional: `""` explicitly means no conditions recorded. Null and
omission are refused on creation. User interfaces may show an optional text area
and serialize blank content as `""`. Whitespace is text, not an implicit clear.

A correction supplies both complete replacement values. An explicit blank
conditions string is frozen, reviewed and applied, clearing earlier recorded
conditions. Approval applies neither field; application commits both together
with one target revision. The unchanged record identifier, person, regulator,
jurisdiction, profession, status and dates remain outside the fixed effect.
The holder reports a transcription or recording error in an existing decision;
selecting another activity is a proposed correction to what that decision already
said, never an application for a new licence or expanded entitlement. The distinct
reviewer checks the existing decision and may reject the proposal.

Entity and route identifiers retain `professional-license`/`professional-licenses`
and `scope-correction`/`scope-corrections`.
