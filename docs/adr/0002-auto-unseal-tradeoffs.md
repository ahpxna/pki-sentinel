# ADR-0002: Transit auto-unseal via a second Vault instead of manual key shards

**Status:** Accepted — 2026-08-01

## Context

Vault with Raft storage starts sealed and normally requires operators to
supply unseal key shards (Shamir) after every restart. That is unworkable for
an automated, idempotent bootstrap (`make bootstrap` / `./scripts/bootstrap.sh`)
that must run unattended in CI and on a developer's laptop alike.

## Decision Drivers

- The bootstrap script must be fully automatic — no human typing unseal keys.
- The reference deployment should demonstrate a transit-seal auto-unseal
  architecture instead of disabling sealing.
- The development-only seal service must be identified as unsuitable for
  production use.

## Considered Options

1. **Shamir unseal keys, manually supplied.** Rejected: blocks automated
   bootstrap and CI.
2. **Transit auto-unseal against a second, dev-mode Vault (`vault-seal`).**
   Chosen for this repository.
3. **Cloud KMS auto-unseal (AWS/GCP/Azure) or HSM.** Suitable for production,
   but dependent on cloud credentials unavailable to a self-contained demo.

## Decision Outcome

Use a second Vault container (`vault-seal`) running in dev mode purely to
host a `transit` engine and an `autounseal` key. The primary `vault`
container's `seal "transit"` stanza points at it. This gives real transit
auto-unseal mechanics (recovery keys instead of unseal keys, automatic
unseal on restart) without requiring cloud credentials.

**This is a development substitute, not a production pattern.** `vault-seal`
runs in-memory development mode: an actor with container access has the
autounseal key, and its own audit trail does not exist. In production this
container is replaced by a cloud KMS or a hardware security module. The
`seal` stanza retains the same purpose with provider-specific configuration.

The transit seal client authenticates via the `VAULT_TOKEN` environment
variable set on the `vault` container (verified against `vault server -help`
and the primary Vault's boot logs), rather than a `token` field in the seal
stanza, because Vault's transit seal reads the client token from the
environment when the config block omits it.

## Consequences

- Positive: `make bootstrap` is fully unattended; recovery keys (not unseal
  keys) are written to `.data/vault-init.json`, matching production recovery
  semantics under auto-unseal.
- Negative: `vault-seal` is a single point of compromise for the whole
  stack's seal material. This is called out in `SECURITY.md` and the
  README's "Production notes" table, with the production fix (cloud
  KMS/HSM) stated explicitly.
- If `vault-seal` is unreachable, `vault` cannot unseal after a restart —
  documented in Appendix C of the master plan / `docs/runbooks/vault-seal-recovery.md`.
