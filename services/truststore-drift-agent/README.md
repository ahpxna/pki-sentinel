# truststore-drift-agent

Detects unauthorized root CA installation by hashing the SubjectPublicKeyInfo
of every root in the host trust store and diffing against a signed baseline.

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
truststore-drift-agent baseline -o truststore-baseline.json
truststore-drift-agent check -b truststore-baseline.json
echo "exit=$?"   # 1 if any unknown root was found
```

`check` exits 1 on drift, so it can be wired into cron or a CI gate.
