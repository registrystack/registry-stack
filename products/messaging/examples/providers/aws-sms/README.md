# AWS End User Messaging SMS provider

This example sends one SMS through the AWS End User Messaging SMS
`SendTextMessage` API. It uses the AWS JSON 1.0 wire protocol and Signature
Version 4 with the `sms-voice` service name. The runtime connection owns the
regional endpoint and credential references; the package scripts see neither.

Install only these package files under the provider id you choose:

```text
providers/aws-sms/provider.yaml
providers/aws-sms/scripts/prepare.rhai
providers/aws-sms/scripts/interpret.rhai
```

Keep this README, `connection.example.yaml`, and `fixtures/` outside the
Messaging project and installed package. If adapting the Messaging starter,
remove its `providers/sms-gateway/` mock directory, create the three paths
above from this example, and change the package manifest to:

```yaml
providers:
  - id: aws-sms
    kind: http
senderProfiles:
  - id: reminders-sms
    channel: sms
    provider: aws-sms
    # Use the AWS E.164 origination number or sender ID for this deployment.
    sender: REGISTRY
    maximumSegments: 2
    onUncertain: hold
```

Do not copy the starter's `idempotentSubmit: true` declaration. AWS
`SendTextMessage` has no client request token, so an uncertain attempt cannot
be safely deduplicated by AWS. `onUncertain: hold` leaves such a message for
operator settlement instead of risking a duplicate.

The Messaging sender-profile contract currently accepts an E.164 number or
an alphanumeric sender ID of at most 11 characters. AWS also accepts pool IDs,
resource IDs, and ARNs for `OriginationIdentity`, but those values do not fit
the current sender-profile contract. A deployment that requires one of those
forms needs that product contract extended before using this example.

Choose an AWS region where AWS End User Messaging SMS is available and where
the origination identity and any required registration are provisioned. These
regional endpoints cover the initial Africa and Southeast Asia deployments:

| Deployment region | `authentication.region` | `baseUrl` |
|---|---|---|
| Africa (Cape Town) | `af-south-1` | `https://sms-voice.af-south-1.amazonaws.com/` |
| Asia Pacific (Singapore) | `ap-southeast-1` | `https://sms-voice.ap-southeast-1.amazonaws.com/` |
| Asia Pacific (Jakarta) | `ap-southeast-3` | `https://sms-voice.ap-southeast-3.amazonaws.com/` |

`authentication.region` must be the region the `baseUrl` endpoint serves,
because AWS refuses a signature scoped to any other region. The runtime does
not compare the two, so a mismatch shows up only as refused sends. A FIPS or
VPC interface endpoint is allowed as `baseUrl` when the deployment needs one;
keep `authentication.region` set to the region that endpoint serves, as
listed in AWS's endpoint reference for the service.
Keep `authentication.service: sms-voice`. Configure the runtime outside the
package; `connection.example.yaml` supplies the members below `type`:

```yaml
providers:
  aws-sms:
    type: http
    baseUrl: https://sms-voice.af-south-1.amazonaws.com/
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
    maximumConcurrentRequests: 8
    redirects: deny
    authentication:
      type: aws-sigv4
      region: af-south-1
      service: sms-voice
      accessKeyIdRef: secret:file/aws-access-key-id
      secretAccessKeyRef: secret:file/aws-secret-access-key
      # Required for temporary AWS credentials.
      # sessionTokenRef: secret:file/aws-session-token
```

Change both regional values together. Resolve every credential reference from
deployment secrets. Write each credential file without a trailing newline, for
example with `printf '%s'` rather than `echo`. The runtime refuses to start
when an access key identifier, secret access key, or session token contains
whitespace or a line break, and names the secret reference without printing
its value; it does not trim the value. Because this package declares
`receipts: none`, do not add `callbackVerifier`.

Explicit secret references are read at startup and never refreshed. Temporary
credentials therefore stop working when their session token expires; AWS then
answers `ExpiredTokenException`, which this example records as the permanent
failure `aws.expired-token`. Rotate the secret files and restart the runtime
before the token expires.

`scripts/prepare.rhai` defaults to a `TRANSACTIONAL` message. Its clearly
marked operator settings can add a configuration set, a maximum price, or a
time to live. Keep those values in the reviewed provider package. IAM should
grant the credential only the `sms-voice:SendTextMessage` action and the
resources the deployment uses.

`scripts/interpret.rhai` classifies AWS answers without reading their error
text. It reads the exception name from the body `__type` member, with or
without a namespace such as `com.amazon.coral.service#` and with any `:`
suffix removed:

| AWS answer | Outcome |
|---|---|
| HTTP 200 with a `MessageId` | accepted |
| HTTP 400 `ThrottlingException` | transient, retried |
| `AccessDeniedException`, `ConflictException`, `ResourceNotFoundException`, `ServiceQuotaExceededException`, `ValidationException` | permanent, `aws.<name>` |
| `ExpiredTokenException`, `IncompleteSignatureException`, `InvalidSignatureException`, `MissingAuthenticationTokenException`, `UnrecognizedClientException` | permanent, `aws.<name>` |
| HTTP 5xx, an unreadable success, or any other answer | maybe-sent |

The credential and signature failures are permanent because AWS refuses such
a request before sending anything, and repeating it cannot succeed until the
operator fixes the credentials. A maybe-sent answer is held under
`onUncertain: hold`.

The example declares no delivery receipts. HTTP 200 with a `MessageId` means
AWS accepted the submission; it does not prove carrier delivery. AWS delivery
events require a configuration set and an event destination, such as SNS,
plus a separately authenticated adapter into Messaging. That bridge is
outside this example.

The wire shape follows the AWS `SendTextMessage` API reference and the
official AWS SDK request snapshot:

- <https://docs.aws.amazon.com/pinpoint/latest/apireference_smsvoicev2/API_SendTextMessage.html>
- <https://github.com/aws/aws-sdk-go-v2/blob/main/service/pinpointsmsvoicev2/request_snapshot/SendTextMessage.request.snap>

Before enabling a destination country, check AWS's maintained guidance:

- [Regional availability and endpoints](https://docs.aws.amazon.com/sms-voice/latest/userguide/what-is-sms-mms.html)
- [Supported destination countries and SMS capabilities](https://docs.aws.amazon.com/sms-voice/latest/userguide/phone-numbers-sms-by-country.html)
- [Choosing an origination identity](https://docs.aws.amazon.com/sms-voice/latest/userguide/phone-number-types.html)
- [Origination identity registration](https://docs.aws.amazon.com/sms-voice/latest/userguide/registrations.html)
