# Runbook: Revocation soft-fail detected

**Trigger:** `RevocationSoftFailDetected` (see `observability/prometheus/rules/pki-slo.yml`)

`AssurancePolicyViolation` uses this runbook as well. It means a profile
matched its documented baseline contract but did not meet the separately
configured organizational policy. It is a warning unless `policy.enforce` is
enabled in `services/revocation-probe/profiles.yaml`.

**Impact:** a client profile with `method != "none"` accepted a certificate
that Vault had already revoked. This means a client that is *supposed* to
check revocation status failed to detect it. This is an enforcement gap,
not the expected "structurally blind" behavior of `method="none"`
profiles (see [ADR-0007](../adr/0007-alerting-on-method-not-none-only.md)).

## Immediate actions

1. Identify the affected profile and method from the alert labels:

   ```bash
   curl -s "http://localhost:${ALERTMANAGER_PORT:-9093}/api/v2/alerts" | jq '.[] | select(.labels.alertname=="RevocationSoftFailDetected")'
   ```

2. Retrieve the signed report and its content-addressed artifacts. Check the
   timeline boundaries before comparing latencies: acknowledgement-to-status,
   status-to-staple publication, and staple-to-client enforcement are distinct
   measures.

3. Confirm the OCSP responder and CRL are healthy. A soft-fail can indicate a
   stale or unreachable responder rather than a client implementation defect:

   ```bash
   curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/ocsp" -o /dev/null -w '%{http_code}\n'
   curl -s "http://localhost:${PROMETHEUS_PORT:-9090}/api/v1/query?query=pki_crl_age_seconds" | jq '.data.result'
   ```

4. Run a manual cycle to determine whether the finding is reproducible:

   ```bash
   make demo-revoke
   ```

5. If reproducible, check whether the affected client's TLS stack or
   configuration changed recently (e.g. a library upgrade that dropped
   `--cert-status` / must-staple support).

## Verification

```bash
# Confirm that the affected profile reports "rejected" after remediation.
make demo-revoke
curl -s "http://localhost:${PROBE_METRICS_PORT:-9110}/metrics" | grep pki_revocation_detected_total
```

## Post-incident

- If the root cause was a genuine client misconfiguration, document the fix
  and consider adding a regression check.
- If the root cause was infrastructure (OCSP responder degraded), see
  [`ocsp-responder-down.md`](ocsp-responder-down.md).
- Update `docs/benchmarks/` if this reveals a new soft-fail condition worth
  tracking as a repeatable measurement.
