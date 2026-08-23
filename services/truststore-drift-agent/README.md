# truststore-drift-agent

Detects unauthorized root CA installation by hashing the SubjectPublicKeyInfo
of every root in the host trust store and diffing against a signed baseline.
Baselines are signed with Ed25519; checks fail closed if the JSON is changed
or the matching public key is unavailable. Runtime scans detect added,
removed, changed, expired, and expiring roots. Keep the private signing key
offline and pin the verification key outside the monitored endpoint in
production.

## Why this exists

The trusted-CA MITM scenario in `docs/benchmarks/trusted-ca-mitm.md` showed
that a client with an attacker CA already installed in its trust store
accepts interception with zero warning and a 100% success rate. That failure
mode is invisible at the TLS layer by construction — the client is doing
exactly what it's configured to do, trust the connection. Detection
therefore has to happen one layer down, at the trust store itself. That is
this agent's entire job.

## Usage

```bash
truststore-drift-agent baseline -o truststore-baseline.json \
  --private-key baseline.key --public-key baseline.pub
truststore-drift-agent check -b truststore-baseline.json --public-key baseline.pub
echo "exit=$?"   # 1 if any unknown root was found

truststore-drift-agent serve -b truststore-baseline.json \
  --public-key baseline.pub --listen :9120 --interval 60s
```

`check` exits 1 on policy drift and 2 when the baseline or scan is invalid.
`serve` exposes `/metrics`, `/events`, `/healthz`, and `/readyz`; Prometheus
scrapes this path in `make up-full`.
Linux certificate bundles/local CA directories and native macOS Keychains are
supported. `--extra-ca-dir <path>` can point both commands at an isolated CA
directory for tests or nonstandard installations.
