# Runbook: Rotate the intermediate CA

**Trigger:** planned rotation (intermediate approaching `int_ttl_hours`),
or emergency rotation after a suspected intermediate key compromise.

**Impact:** every leaf certificate issued by the current intermediate must
eventually be re-issued under the new one. Because leaf TTLs are short
(24h — see [ADR-0003](../adr/0003-short-lived-certs-over-revocation.md)),
routine rotation is low-drama: stop issuing from the old intermediate and
let the 24h TTL naturally cycle every leaf onto the new one.

## Immediate actions (emergency: suspected intermediate key compromise)

1. Revoke the compromised intermediate at the root:

   ```bash
   cd terraform/bootstrap
   VAULT_ADDR="http://localhost:${VAULT_PORT:-8200}" VAULT_TOKEN="$(cat ../../.data/tf-token)" \
     vault write pki_root/root/rotate/internal common_name="${ORG_NAME} Root CA R2"
   ```

2. Generate and sign a new intermediate CSR, following the same three-step
   chain as Step 1.5 (`pki_int.tf`), pointed at the new root.

3. Update `pki_int/config/ca_chain` / re-run `terraform apply` so `pki_int`
   trusts the new root's signature.

## Routine rotation (no compromise)

```bash
cd terraform/bootstrap
terraform plan   # review the new intermediate CSR/sign/set-signed diff
terraform apply -auto-approve
```

## Verification

```bash
curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/ca_chain" > /tmp/new-chain.pem
openssl crl2pkcs7 -nocrl -certfile /tmp/new-chain.pem | openssl pkcs7 -print_certs -noout
openssl verify -CAfile <(curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_root/ca/pem") \
  <(curl -s "http://localhost:${VAULT_PORT:-8200}/v1/pki_int/ca/pem")
```

## Post-incident

If this was an emergency rotation, write a postmortem and update
`docs/threat-model.md` if the compromise revealed a gap not already listed.
