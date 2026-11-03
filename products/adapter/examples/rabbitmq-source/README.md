# RabbitMQ source runtime example

This example supplies the operator-owned runtime binding for a pack endpoint
named `institution-events`. Build `adapter-job` with `job-rabbitmq`; the
feature is off by default. The authored source route must poll
`rabbitmq:institution-events` with decoder `rabbitmq-json`. One broker message
is one JSON value and one job item.

Before using the example:

1. Provision a dedicated broker principal with no administrative tag and these
   anchored, literal-name permissions for the configured resources (escape
   regular-expression metacharacters in the actual names):

   - configure: `^(SOURCE_QUEUE|DEAD_LETTER_EXCHANGE|DEAD_LETTER_QUEUE)$`
   - write: `^(DEAD_LETTER_EXCHANGE|DEAD_LETTER_QUEUE)$`
   - read: `^(SOURCE_QUEUE|DEAD_LETTER_EXCHANGE)$`

   The host uses non-passive declarations. Declaring the source queue with a
   DLX needs configure and read on that queue plus write on the DLX; declaring
   the DLX and DLQ needs configure; binding the DLQ needs write on the queue
   and read on the exchange. These checks follow RabbitMQ's
   [AMQP 0-9-1 permission table](https://www.rabbitmq.com/docs/access-control)
   and [DLX permission rule](https://www.rabbitmq.com/docs/dlx).
2. Require AMQPS. Use system roots, or replace `caBundleFile` with an absolute
   path to the deployment's private CA bundle.
3. Provide `RABBITMQ_SOURCE_PASSWORD` through the process secret provider.
4. Configure the broker's hard `max_message_size` no higher than the job
   profile's `maximumRowBytes`. The client check occurs after Lapin has
   assembled one body and is not a broker-setting attestation.
5. Publish every immutable event with a unique stable AMQP `message-id`, a
   single JSON body, and `delivery_mode=2` (persistent). Use publisher confirms
   and proceed only after the broker confirms the publish. The source refuses
   a delivery without mode 2 to the DLQ, but a consumer cannot observe whether
   the producer received a publisher confirm. RabbitMQ documents these as
   separate reliability mechanisms in its
   [reliability](https://www.rabbitmq.com/docs/reliability) and
   [publisher-confirm](https://www.rabbitmq.com/docs/confirms) guidance.
   Reusing an identity for changed bytes or changed reviewed projection is
   held, never applied or acknowledged automatically.
6. Monitor the DLQ and held-item status. An explicit item refusal is written
   durably before rejection routes it to the DLQ. A held delivery stays
   unsettled and can block later messages at the queue head.

`maximumOutstandingDeliveries` is the local unsettled-delivery bound.
`basic.get` is not constrained by broker QoS or prefetch. Queue dry-run is
refused before acquisition because AMQP provides no side-effect-free peek.
Acknowledgement and rejection share the finite poll deadline. An uncertain
settlement stops the pass and reconnects on a later bounded read so a stable
redelivery can recover without repeating an accepted destination effect.

See [`job-runtime.example.yaml`](job-runtime.example.yaml) for the binding.
