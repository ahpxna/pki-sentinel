# Runbook: Root CA compromise

**Trigger:** confirmed or strongly suspected compromise of the root CA
private key material (`pki_root` mount). This is the worst-case incident
in the entire system — with a properly bootstrapped hierarchy, `pki_root`
is written to exactly once (see [rule 100102](../../observability/wazuh/rules/local_rules.xml),
"Root CA mount written — should essentially never happen").

**Impact:** total trust failure. Every certificate the root has ever signed
(directly or via the intermediate) must be considered untrustworthy.

## Immediate actions

1. Confirm the scope: was it the root key itself, or only the intermediate?
   Check for rule 100102 firings, which should be extremely rare/never:

   ```bash
   docker compose exec wazuh-manager grep -c '100102' /var/ossec/logs/alerts/alerts.json
   ```

2. If the root key is confirmed compromised, treat the entire PKI as
   burned. Do not attempt to "clean up" the existing hierarchy — stand up a
   new root:

   ```bash
   cd terraform/bootstrap
   terraform destroy -target=vault_pki_secret_backend_root_cert.root -auto-approve
   terraform apply -auto-approve   # generates a fresh root + re-signs a new intermediate
   ```

3. Every client and service trust bundle referencing the old root's
   fingerprint must be redistributed with the new chain:

   ```bash
   make ca-chain   # writes the new .data/ca_chain.pem
   ```

4. Communicate the incident and the new chain fingerprint to all consumers
   before they lose connectivity as old certs expire.

## Verification

```bash
openssl x509 -in .data/ca_chain.pem -noout -subject -issuer
# confirm the subject is the NEW root/intermediate, not the compromised one
```

## Post-incident

- Write a full postmortem; this incident class is severe enough to warrant
  external disclosure if any relying party's trust was affected.
- Review why detection didn't happen sooner — rule 100102 exists precisely
  to catch this class of event immediately, not after the fact.
- Consider whether the production remediation in the README's "Production
  notes" (offline root on HSM/smartcard) would have prevented this
  specific compromise path.
