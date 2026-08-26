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

2. Confirm `vault-seal` (the persistent local transit auto-unseal key holder; see
   [ADR-0002](../adr/0002-auto-unseal-tradeoffs.md)) is healthy and its
   `transit/keys/autounseal` key still exists:

   ```bash
   docker compose ps vault-seal
   docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
     vault-seal vault read transit/keys/autounseal
   ```

3. If `vault-seal` is down, restart it and then restart `vault`. Its Raft data
   volume must remain intact; never delete `.data/vault-seal` during recovery:

   ```bash
   docker compose restart vault-seal
   source scripts/lib/wait_for.sh
   wait_for_cmd 60 docker compose exec -T vault-seal vault status
   docker compose restart vault
   ```

4. If the transit key is missing or the seal volume was deleted, automatic
   recovery is not possible. Do not use the primary Vault recovery keys as
   unseal keys; under transit auto-unseal they can only generate a temporary
   administrative token. Restore `.data/vault-seal` from its protected backup
   or recreate the disposable lab and reinitialize the primary Vault.

   ```bash
   jq -r '.recovery_keys_b64[]' .data/vault-init.json
   # Use the documented `vault operator generate-root` flow only when
   # administrative access is required and the transit seal is available.
   ```

## Verification

```bash
curl -s "http://localhost:${VAULT_PORT:-8200}/v1/sys/health" | jq -e '.sealed == false'
```

## Post-incident

Loss of the persistent seal volume is a key-management incident, not a normal
restart. Restore the volume and verify the transit key before restarting the
primary; if no backup exists, treat the lab as unrecoverable and rebuild it.
