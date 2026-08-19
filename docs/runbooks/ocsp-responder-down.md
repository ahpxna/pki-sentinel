# Runbook: OCSP responder down / CRL stale

**Trigger:** `OCSPResponderDown` or `CRLStale` (see `observability/prometheus/rules/pki-slo.yml`)

**Impact:** clients that do check revocation can no longer get a fresh
answer. Per `docs/benchmarks/ocsp-softfail-thresholds.md`, a degraded rather
than fully unavailable responder can push soft-fail rates toward 100%; an
attacker does not need to fully block the path.

## Immediate actions

1. Distinguish responder unavailability from high response latency:

   ```bash
   curl -s -o /dev/null -w '%{http_code} %{time_total}s\n' "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/ocsp"
   ```

2. Check Vault health and logs:

   ```bash
   curl -s "http://localhost:${VAULT_PORT:-8200}/v1/sys/health" | jq .
   docker compose logs --tail=200 vault
   ```

3. Check CRL age and rebuild configuration:

   ```bash
   curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/crl" -o /tmp/current.crl
   openssl crl -in /tmp/current.crl -inform DER -noout -nextupdate -lastupdate
   ```

4. If the `vault` container is unhealthy, check whether the seal
   Vault (`vault-seal`) is reachable — the primary depends on it for
   auto-unseal on restart. See
   [`vault-seal-recovery.md`](vault-seal-recovery.md).

## Verification

```bash
curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/acme/directory" | jq -e '.newNonce'
curl -s "http://localhost:${PROMETHEUS_PORT:-9090}/api/v1/query?query=pki_ocsp_responder_up" | jq '.data.result[0].value[1]'
# expect "1"
```

## Post-incident

Update the alert's `for:` duration or `ocsp_expiry` (Step 1.6) when expected
responder churn, such as a Vault restart during routine deployment, caused a
false positive.
