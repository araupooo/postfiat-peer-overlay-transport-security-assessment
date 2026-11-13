# Primary sources

Consulted while writing, 2026-11-13. The pack itself makes no
network calls; the facts taken from each source are listed so a
reviewer can re-check them.

## Standards

- RFC 8446 (IETF, Aug 2018), *The Transport Layer Security (TLS)
  Protocol Version 1.3*: TLS 1.3 removes RSA key transport and
  static DH, mandates ephemeral (EC)DHE key exchange, defines 5
  cipher suites, all AEAD; no compression, no renegotiation.
  Used for: the forward-secrecy claims in `tls_audit.md` and
  `exposure_analysis.md`.
- RFC 10024 (IETF, Aug 2026), *Post-Quantum Traditional (PQ/T)
  Hybrid Key Agreement Mechanisms for TLS 1.3*: hybrid groups
  `X25519MLKEM768` (code point `0x11EC`), `SecP256r1MLKEM768`
  (`0x11EB`), `SecP384r1MLKEM1024` for TLS 1.3. Used for: the
  hybrid group name and code point in `hybrid_migration.md`.
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism
  Standard* (ML-KEM), final, 13 Aug 2024. Three parameter sets:
  ML-KEM-512 (encapsulation key 800 bytes, ciphertext 768 bytes),
  ML-KEM-768 (1,184 / 1,088 bytes), ML-KEM-1024 (1,568 / 1,568
  bytes); shared secret 32 bytes for all three; ML-KEM-768 is the
  recommended default. Used for: ML-KEM sizes in
  `hybrid_migration.md`.
- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*
  (ML-DSA), final, 13 Aug 2024. ML-DSA-65: public key 1,952 bytes,
  signature 3,309 bytes (Table 2). Used for: the node-identity
  open question in `hybrid_migration.md`.

## Quantum threat model

- P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization
  and Discrete Logarithms on a Quantum Computer", *SIAM Journal on
  Computing* 26(5), 1997: factoring and discrete logarithms in
  polynomial time — breaks RSA, DH, ECDH, ECDSA and secp256k1.
  Used for: every harvest-now-decrypt-later and forge-later rating.
- L. K. Grover, "A fast quantum mechanical algorithm for database
  search", 1996: unstructured search in ~√N steps — halves
  effective symmetric/hash strength. Used for: the AES-256
  (~128-bit quantum security) note in `exposure_analysis.md`.

## Library / ecosystem facts

- OpenSSL 1.1.1 end of support: 11 Sep 2023; last release 1.1.1w
  (12 Sep 2023). Source: OpenSSL project, "OpenSSL 1.1.1 End Of
  Life Approaching" (15 June 2023),
  https://openssl-library.org/post/2023-06-15-1.1.1-eol-reminder/ .
  The tree pins `openssl/1.1.1w` in `conanfile.py:30`.
- OpenSSL 1.1.1 added TLS 1.3 support (NEWS.md, "Major changes
  between OpenSSL 1.1.0i and OpenSSL 1.1.1 [11 Sep 2018]":
  "Support for TLSv1.3 added ... Fully compliant implementation
  of RFC8446 (TLSv1.3) on by default ... Support for all five
  RFC8446 ciphersuites"). Used for: the claim that the pinned
  library can negotiate TLS 1.3.
- OpenSSL 3.5 final release, 8 Apr 2025: native support for
  ML-KEM, ML-DSA and SLH-DSA, including hybrid TLS groups
  `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`;
  LTS supported to 8 Apr 2030; the default TLS group list includes
  and prefers the hybrid groups. Source: OpenSSL project release
  announcement, https://openssl-library.org/post/2025-04-08-openssl-35-final-release
  (as summarised by the secondary sources consulted 2026-11-13).
  Before 3.5 the only PQC path was the external OQS provider.
  Used for: the migration blocker and sequencing in
  `hybrid_migration.md`.
- OpenSSL documentation, `SSL_CTX_set_cipher_list(3)`:
  "SSL_CTX_set_cipher_list() sets the list of available ciphers
  (TLSv1.2 and below) ... This function does not affect TLSv1.3
  ciphersuites. Use SSL_CTX_set_ciphersuites() to configure
  those." Default TLS 1.3 ciphersuites:
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256".
  Source: https://docs.openssl.org/master/man3/SSL_CTX_set_cipher_list/ .
  Used for: the TLS 1.3 ciphersuite claims in `tls_audit.md`.

## Codebase facts (primary source: the pinned tree itself)

- postfiatd, commit `0085a1ff885d6a446369cf73a4430f75af22be55`.
  All file:line citations in this pack come from this tree.
- Sibling work reused, not re-derived: the cryptographic
  inventory pack (TLS context paths, OpenSSL pin, RSA
  certificate generation) and the validator key-lifecycle pack
  (claim-to-evidence index format). The TLS facts in this pack
  were re-checked against the pinned tree by direct reading and
  grep; where the sibling pack's paths were wrong (it cited
  `src/libxrpl/overlay/detail/OverlayImpl.cpp` — the file is at
  `src/xrpld/overlay/detail/OverlayImpl.cpp`), this pack uses
  the corrected path.
