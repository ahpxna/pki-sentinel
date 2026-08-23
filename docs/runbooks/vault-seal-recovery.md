# Runbook: Vault seal recovery

**Trigger:** `vault` container is sealed and does not auto-unseal after a
restart (see Appendix C symptom "Vault stays sealed after bootstrap").

**Impact:** total Issuance-plane outage — no certs can be issued, renewed,
or revoked while Vault is sealed.

## Immediate actions

1. Confirm the seal state and check logs for the specific failure:

   ```bash
   curl -s "http://localhost:${VAULT_PORT:-8200}/v1/sys/health" | jq '.sealed, .initialized'
   docker compose logs --tail=200 vault | grep -i seal
   ```

2. Confirm `vault-seal` (the development transit auto-unseal key holder; see
   [ADR-0002](../adr/0002-auto-unseal-tradeoffs.md)) is healthy and its
   `transit/keys/autounseal` key still exists:

   ```bash
   docker compose ps vault-seal
   docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
     vault-seal vault read transit/keys/autounseal
   ```

3. If `vault-seal` is down, restart it and then restart `vault`:

   ```bash
   docker compose restart vault-seal
   source scripts/lib/wait_for.sh
   wait_for_cmd 60 docker compose exec -T vault-seal vault status
   docker compose restart vault
   ```

4. If auto-unseal still fails, use recovery keys as the final recovery
   mechanism:

   ```bash
   jq -r '.recovery_keys_b64[]' .data/vault-init.json
   # For each key:
   # docker compose exec vault vault operator unseal <key>
   ```

## Verification

```bash
curl -s "http://localhost:${VAULT_PORT:-8200}/v1/sys/health" | jq -e '.sealed == false'
```

## Post-incident

Use of recovery keys indicates a defect in the transit auto-unseal
configuration. File an issue with the `vault` and `vault-seal` container
logs attached.
