# Assumptions, limits, and open questions

Read before citing any number in this pack.

## Scope

- **Local rig only.** The harness stands up a TLS client/server
  pair on loopback, configured like the overlay. It is **not** a
  measurement of live peer connections. No live peer, validator or
  network endpoint was contacted. Negotiated versions and suites
  between real peers depend on the remote peer's offered list,
  which is not observable statically.
- **No build, no run.** A local build/run of the ledger is not
  feasible on this machine (no Conan, ~1 GB RAM; the build needs
  Conan-managed dependencies and a multi-GB toolchain). Nothing in
  this pack claims the ledger was compiled or executed. The audit
  is static reading of the pinned tree plus the local TLS rig.
- **Pinned tree only.** Every code claim is against postfiatd main
  commit `0085a1ff885d6a446369cf73a4430f75af22be55`. Behaviour on
  any other commit, including later main, is not covered.

## Tool-version dependence (recorded, not hidden)

- The harness ran against local OpenSSL **3.0.13** (library and
  CLI), Python 3.12.3. The pinned library is **1.1.1w**.
- Cipher-suite **counts** (31 / 27 / 71 / 3) are measured under
  3.0.13 and will differ under 1.1.1w, whose DEFAULT and ALL suite
  sets differ from 3.0.13's. The *shape* of the findings — RSA key
  transport still permitted, CBC excluded, TLS 1.3 suites untouched
  by the cipher list — follows from the cipher string and the
  OpenSSL API and does not depend on the version. Exact counts under
  1.1.1w are **not verified** and are not claimed.
- TLS 1.3 suite count under 3.0.13 is 3 (the two CCM suites from
  RFC 8446 are not offered by this build). Under 1.1.1w all five
  RFC 8446 suites are supported per the 1.1.1 NEWS entry; the
  harness does not measure that.
- The deterministic test certificate fixes the serial and validity
  window (fixed values recorded in `harness.py`); the real code
  draws the serial from `BN_rand` and the validity window from the
  wall clock at server start, and draws its RSA key from OpenSSL's
  CSPRNG rather than a seeded PRNG. The certificate is a throwaway
  test artifact, never used outside loopback; its private key is
  shipped in the pack (`results/test_key.pem`) precisely because
  it is worthless — do not reuse it anywhere else.

## Harness limits

- The Python `ssl` module exposes no API to set temporary DH
  parameters, so the DHE variant (V9) runs through the `openssl`
  CLI server (`s_server` with the embedded DH parameters) instead
  of the Python server. The negotiated result is recorded the same
  way; the mechanism differs and is disclosed in `harness.py`.
- The harness cannot observe the negotiated TLS 1.3 **named
  group** (e.g. X25519 vs secp256r1) through the Python `ssl`
  API, so no claim is made about which group negotiates — only
  about version and suite.
- The harness performs full handshakes only; session resumption
  and 0-RTT are not exercised, and no claim is made about them.
- Variant V9 runs a single attempt (one `s_server` invocation);
  all other variants run 3 attempts each. All attempts agreed
  within each variant.

## Configuration-dependent facts (not determinable statically)

- Whether an operator overrides the cipher list with
  `ssl_ciphers`, or supplies their own RPC certificate.
- Whether WorkSSL verifies certificates in a given deployment
  (depends on the operator's `SSL_VERIFY` configuration).
- Which TLS version/suite a given live peer connection negotiates.

## Open questions (carried from the documents)

- OpenSSL 3.5 upgrade scope: how much of the tree breaks against
  3.x, and the EVP rewrite of `initAnonymous` (see
  `hybrid_migration.md`, open question 1).
- ML-DSA for peer authentication / node identity (open
  question 2): transport hybridisation does not cover it.
- Whether to drop RSA key-transport suites from the cipher list
  as a separate classical hardening step (open question 3).
- WorkSSL migration to TLS 1.3 (open question 4).
- Per-connection logging of negotiated TLS parameters does not
  exist in the tree today (open question 5); without it the
  hybrid rollout cannot be verified in production.
- FIPS-validated module availability for native ML-KEM (open
  question 6).
