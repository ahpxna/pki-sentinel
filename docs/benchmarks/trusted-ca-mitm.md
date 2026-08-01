# Trusted-CA MITM

## Scenario A: untrusted CA

An interception proxy presents a certificate signed by a CA the client does
not trust. Result across all trials: 0% interception success — every
client correctly rejected the connection with a visible TLS error. This is
the TLS trust model working exactly as designed.

## Scenario B: trusted CA

The same interception proxy, but its CA has been installed into the
client's trust store beforehand (the classic corporate-proxy / malware
pattern). Result across all trials: 100% interception success, full
plaintext visible to the interceptor, **no client-side warning of any
kind.**

## Why this failure mode is undetectable at the TLS layer

This is not a bug in any client — it's the trust model functioning exactly
as designed. A client that trusts a CA will, by construction, trust
everything that CA signs. There is no TLS-layer signal to distinguish "your
organization's legitimate root CA" from "a CA an attacker convinced you (or
malware convinced your OS) to install." Detection has to happen one layer
down, at the trust store itself, which is precisely what
[`truststore-drift-agent`](../../services/truststore-drift-agent/README.md)
does: hash every root's SubjectPublicKeyInfo and diff against a signed
baseline. A rogue CA installed after the baseline was taken shows up as an
`unknown_root` event and a non-zero `pki_truststore_unknown_roots` gauge,
regardless of whether any TLS connection was ever intercepted.

See `make truststore-drift-demo` for a runnable reproduction (installs a
synthetic rogue CA into a container-local demo trust store — never the
developer's real machine — and shows the agent detect it, exit code 1).
