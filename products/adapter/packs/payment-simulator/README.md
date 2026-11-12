# Synthetic payment provider pack

This reviewed pack selects the built-in `simulator-p2g/v1` connector for the
typed Payment Adapter. It is a local test profile. It never moves money.

The pack fixes the connector and advertised collection capability. A deployment
still supplies its own provider origin, tenant, biller, currency policy,
credential references and BReg binding in `AdapterPayments` configuration.
The connection pins the exact pack bytes; start the host with
`--payment-provider-pack` pointing to this file. The connector implementation
is compiled into `adapter`; the pack cannot execute arbitrary code.

Check the artifact with `adapterctl payments check-pack pack.yaml`, then check
the deployment with `adapterctl payments check payments.yaml --provider-pack
pack.yaml`.
