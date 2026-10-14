# Regional review with routing and clocks

This submitted-context policy sends a northern request to `northern-review` from
its submitted `region`; other requests start in `triage`. Approval advances to a
separate supervisor signoff stage. The two clocks pin an elapsed response budget
and an office-calendar deadline, whose due step reassigns overdue work.

Run the offline authoring checks from the repository root:

```sh
caseworkctl check products/casework/examples/multi-stage-routing-clocks
caseworkctl explain products/casework/examples/multi-stage-routing-clocks
caseworkctl test products/casework/examples/multi-stage-routing-clocks
```

`test` validates the synthetic review display and policy outcome vocabulary. It
does not start PostgreSQL or prove a runtime decision. The checkpoint runner
also checks the compiled stage, route, and clock closure. An operator supplies
the live `office-holidays` revision through the calendar administration API;
`holiday-sets/office-holidays-7.yaml` is an example of that revision format.

The offline fixture uses `region: south` and checks the first stage's base queue, `triage`.
`caseworkctl test` validates display and declared expectations without running the routing engine.
Use `explain` to inspect the compiled northern route; real routing behavior is covered by the
maintained ReviewTask routing tests.
