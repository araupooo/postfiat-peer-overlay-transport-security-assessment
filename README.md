# Post-Quantum Peer-Overlay Transport Security Assessment

Transport-security assessment of the postfiatd peer overlay under
a post-quantum threat model: a TLS configuration audit of the
pinned tree, a runnable local handshake-behavior harness, a
harvest-now-decrypt-later exposure analysis per traffic class, and
a hybrid ML-KEM transport migration design.

**Canonical results page: `docs/index.html`.**

## Pinned tree

- Repository: postfiatd
- Commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
- A local checkout of that commit was used for the audit and for
  the harness (DH parameter extraction, commit recording). The
  harness records the tree's `HEAD` commit in
  `results/handshake_results.json`, so a wrong tree is detectable.

## Headline findings

- **Peer TLS is TLS 1.2 / 1.3 with a 2048-bit RSA self-signed
  certificate, and no certificate verification.** The overlay
  context is `make_SSLContext("")`; verification is `verify_none`
  on both ends. Peer authentication comes from the overlay
  handshake above TLS (secp256k1 node key signing a value derived
  from the TLS Finished messages), not from TLS.
- **Cipher list as written:
  `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`.** It expands to 31 TLS
  1.2 suites under the local OpenSSL. It excludes every CBC suite,
  but it **still permits RSA key transport**: 8 RSA suites remain,
  and harness variant V5 negotiates
  `TLS_RSA_WITH_AES_256_GCM_SHA384` against the overlay
  configuration. RSA key transport has no forward secrecy.
- **TLS 1.3 is allowed and is what negotiates by default**
  (variant V1: TLS 1.3, `TLS_AES_256_GCM_SHA384`). The cipher list
  does not touch TLS 1.3 suites at all — the code never calls
  `SSL_CTX_set_ciphersuites` — so all default TLS 1.3 suites are
  available.
- **Harvest-now-decrypt-later exposure is concentrated in TLS 1.2
  sessions.** TLS 1.3 sessions use ephemeral (EC)DHE only and are
  forward-secret against a later quantum adversary. A TLS 1.2
  session negotiated with an RSA suite is decryptable by anyone
  who later obtains the server's RSA private key. Exposure per
  traffic class: Medium for peer-overlay, RPC and outbound work
  traffic alike — see `exposure_analysis.md` for the per-class
  rationale (the overlay key is ephemeral per process start, which
  narrows the window; RPC operator certificates may be long-lived,
  which widens it; WorkSSL is TLS 1.2-only).
- **Hybrid ML-KEM migration is blocked on the pinned OpenSSL, not
  on the protocol.** OpenSSL 1.1.1w has no ML-KEM support; native
  ML-KEM arrived in OpenSSL 3.5 (8 April 2025). The first step is
  the OpenSSL upgrade, then enabling the `X25519MLKEM768` hybrid
  group (RFC 10024). The overlay's above-TLS peer authentication
  (secp256k1 node keys) is a separate, harder migration.

## Reproduce

Requirements: Python 3.8+ (standard library only), a checkout of
the pinned tree, the system `openssl` CLI (cipher expansion, DH
check, DHE server/client), `git` (only to record the tree commit),
`sha256sum`. No network access is used at any step; all handshakes
run on loopback (127.0.0.1).

```sh
# 1. Run the harness and regenerate every derived output:
POSTFIATD_TREE=/path/to/postfiatd-tree-at-0085a1ff ./run_all.sh

# 2. Verify the digest manifest:
./verify_digests.sh --check
```

`run_all.sh` runs `harness.py` (writes `results/handshake_results.json`,
`results/cipher_matrix.csv`, `results/cert_properties.json`,
`results/dh_params.txt`, `results/dh_params.pem`, `results/test_cert.pem`,
`results/test_key.pem`, `results/summary.txt`), then `build_derived.py`
(writes `results/cipher_matrix.md` and `docs/index.html`), then
`verify_digests.sh` (rebuilds `SHA256SUMS`). The harness output is
deterministic: the test RSA key is generated from a fixed seed
(20261113) and the test certificate uses a fixed serial and validity
window, so two runs produce byte-identical outputs. See
`REPRODUCTION.md` for the fresh-environment reproduction record.

Tool versions used at authoring time: Python 3.12.3, OpenSSL 3.0.13
(library and CLI), git 2.43.0, GNU coreutils `sha256sum` (Ubuntu).

## Pack contents

| File | What it is |
|---|---|
| `docs/index.html` | Canonical results page |
| `tls_audit.md` | TLS configuration audit (all three context paths, versions, cipher suites, certificates) |
| `exposure_analysis.md` | Harvest-now-decrypt-later analysis per traffic class |
| `hybrid_migration.md` | Hybrid ML-KEM transport migration design, fallback, rollback, open questions |
| `harness.py` | Loopback handshake-behavior harness (stdlib only + system `openssl` CLI) |
| `results/handshake_results.json` | Machine-readable harness results (10 variants, cipher counts, cert properties) |
| `results/cipher_matrix.csv`, `results/cipher_matrix.md` | Cipher-negotiation matrix (74 suites) |
| `results/cert_properties.json` | Measured properties of the generated test certificate |
| `results/dh_params.txt`, `results/dh_params.pem` | Embedded DH parameters: check output and extracted parameters |
| `results/test_cert.pem`, `results/test_key.pem` | Deterministic throwaway test certificate/key (loopback only; the key is worthless — do not reuse it) |
| `results/summary.txt` | One-page harness summary |
| `build_derived.py` | Regenerates `results/cipher_matrix.md` and `docs/index.html` |
| `claim_evidence_index.md` | Every headline claim mapped to file, field and line |
| `sources.md` | Primary sources |
| `assumptions.md` | Assumptions, limits, open questions |
| `run_all.sh`, `verify_digests.sh`, `SHA256SUMS` | Reproduction and integrity |
| `REPRODUCTION.md` | Fresh-environment reproduction record |

## Scope and limits (read before citing the results)

- **Local rig only.** The harness measures a TLS client/server pair
  configured like the overlay; it is **not** a measurement of live
  peer connections — no live peer, validator or network endpoint
  was contacted.
- **No build, no run.** A local build/run of the ledger is not
  feasible on this machine. Nothing in this pack claims the ledger
  was compiled or executed.
- **Tool-version dependence.** Cipher-suite counts are measured
  under local OpenSSL 3.0.13; the pinned library is 1.1.1w. Exact
  counts under 1.1.1w were not measured. The shape of the findings
  does not depend on the version — see `assumptions.md`.
- **Configuration-dependent facts** (operator `ssl_ciphers`
  overrides, operator RPC certificates, WorkSSL verification
  settings) cannot be determined statically.
