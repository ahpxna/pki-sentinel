# ADR-0007: Alerting on `method != "none"` only

**Status:** Accepted — 2026-08-01

## Context

`RevocationSoftFailDetected` (`observability/prometheus/rules/pki-slo.yml`)
is the highest-severity alert in the system: a client accepted a revoked
certificate. But several baseline profiles (`curl-default`, `go-tls-default`,
`python-requests`) are *expected* to accept every single cycle, because they
perform no revocation check by default — that is documented, known,
unsurprising behavior, not a defect discovered at 3am.

## Decision Drivers

- Paging on an expected, structural property of a client produces alert
  fatigue and trains responders to ignore the alert.
- The distinction between "this client is blind to revocation by design"
  and "this client checks and still got it wrong" is safety-critical and
  must be visible somewhere, just not in PagerDuty.

## Considered Options

1. Alert on every soft-fail, including `method="none"` profiles.
2. Alert only on `method != "none"` soft-fails; still count and display
   `method="none"` profiles on the Grafana dashboard as the "structurally
   blind" cohort.

## Decision Outcome

Option 2. `RevocationSoftFailDetected`'s PromQL expression explicitly
excludes `method="none"`:
```
increase(pki_revocation_softfail_total{method!="none"}[30m]) > 0
```
The `method="none"` cohort is still fully recorded in
`pki_revocation_softfail_total` and shown in the "Profile × Method × Last
Outcome" table on the `revocation-slo` dashboard — it's a reporting
concern, not a paging concern.

## Consequences

- Positive: on-call only pages for a client that checks revocation and
  still accepted a revoked cert — an actual enforcement failure.
- Negative: an operator glancing only at Alertmanager, never at Grafana,
  could mistakenly believe every client in the fleet checks revocation.
  The dashboard's structurally-blind cohort column exists specifically to
  prevent that misreading; `docs/runbooks/revocation-softfail.md` states
  this distinction explicitly.
