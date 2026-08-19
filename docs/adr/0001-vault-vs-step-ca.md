# ADR-0001: HashiCorp Vault (PKI secrets engine) over step-ca or Boulder

**Status:** Accepted — 2026-08-01

## Context

pki-sentinel needs a PKI engine that issues short-lived leaf certificates, runs
an ACME endpoint, exposes CRL/OCSP, and integrates with secret management for
the AppRole identity model used by `demo-api` and `revocation-probe`.
Candidates considered: HashiCorp Vault / OpenBao PKI secrets engine, Smallstep
`step-ca`, and Let's Encrypt's Boulder.

## Decision Drivers

- Licensing (BUSL vs Apache-2.0) and its effect on a reference repository
  meant to be freely cloned and run.
- Synergy with secret management (KV, AppRole, transit) so one platform
  serves both PKI and application secrets.
- Operational weight — how much infrastructure is needed to get a working
  ACME + CRL/OCSP responder.

## Considered Options

1. **HashiCorp Vault** — mature PKI secrets engine, native ACME support
   (added in Vault 1.14+), CRL/OCSP built in, AppRole auth and KV-v2 in the
   same binary.
2. **OpenBao** — Apache-2.0 fork of Vault, API-compatible, drop-in
   replacement (`openbao/openbao` image is documented as an alternative in
   `.env.example`).
3. **Smallstep step-ca** — purpose-built ACME CA, lighter weight, but no
   built-in secret management, so a second system (Vault KV or similar)
   would still be needed for AppRole/KV.
4. **Boulder** — the production Let's Encrypt CA software; heavyweight
   (multiple databases, gRPC services), designed for public CA operation at
   Let's Encrypt's scale, not a good fit for an SME-internal PKI demo.

## Decision Outcome

Use HashiCorp Vault (BUSL-licensed as of 1.15) as the reference implementation,
with OpenBao documented as an Apache-2.0 drop-in alternative when an
open-source license is required. Vault combines PKI, secret management, and
authentication in one platform. Its ACME support also allows Traefik to
obtain certificates without manual issuance steps.

## Consequences

- Positive: one platform to operate, well-documented Terraform provider,
  native ACME/CRL/OCSP.
- Negative: Vault's BUSL license means a fully-commercial fork is not
  free to use in some contexts; OpenBao exists specifically to address this
  and is a one-line image swap in `.env.example`.
- The AppRole and KV-v2 patterns used by `demo-api` would need to be
  reimplemented against a separate secret store if step-ca were chosen
  instead.
