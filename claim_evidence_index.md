# Claim-to-evidence index

Every headline claim in this pack, mapped to the repo file, field,
and line that holds it. Line numbers refer to the files as published
in this repository. Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Harness:
`harness.py` 1.0.0, seed 20261113, 10 variants (V1–V8 and V10: 3
attempts each; V9: 1 attempt via the `openssl` CLI server), loopback
only, local OpenSSL 3.0.13 (library and CLI), Python 3.12.3.

## Measured claims (from running the harness)

| # | Claim | Evidence |
|---|-------|----------|
| M-01 | Overlay configuration as written negotiates TLS 1.3 with `TLS_AES_256_GCM_SHA384` (3/3 attempts) | `results/handshake_results.json`, variant V1 summary, lines 137-141 (`"attempts": 3`, `"successes": 3`, `"negotiated_version": "TLSv1.3"`, `"negotiated_cipher": "TLS_AES_256_GCM_SHA384"`); `results/summary.txt`, line 15; `tls_audit.md`, line 210 |
| M-02 | TLS 1.3-only variant negotiates TLS 1.3 with `TLS_AES_256_GCM_SHA384` (3/3) | `results/handshake_results.json`, variant V2 summary, lines 185-189; `results/summary.txt`, line 16; `tls_audit.md`, line 211 |
| M-03 | Overlay cipher list under TLS 1.2 negotiates `ECDHE-RSA-AES256-GCM-SHA384` (3/3) | `results/handshake_results.json`, variant V4 summary, lines 281-285; `results/summary.txt`, line 18; `tls_audit.md`, line 213 |
| M-04 | Relaxed cipher list (`ALL`) under TLS 1.2 negotiates the same suite, `ECDHE-RSA-AES256-GCM-SHA384` (3/3) — the relaxation changes nothing for a default client | `results/handshake_results.json`, variant V3 summary, lines 233-237; `results/summary.txt`, line 17; `tls_audit.md`, line 212 |
| M-05 | The overlay configuration permits RSA key transport: a client offering only `AES256-GCM-SHA384` negotiates `TLS_RSA_WITH_AES_256_GCM_SHA384` under TLS 1.2 (3/3) | `results/handshake_results.json`, variant V5 summary, lines 329-333 (`"negotiated_cipher": "AES256-GCM-SHA384"`); `results/summary.txt`, line 19; `tls_audit.md`, line 214; `results/cipher_matrix.csv`, line 9 (`AES256-GCM-SHA384,1.2,RSA,RSA,AEAD,no,yes,yes,yes`) |
| M-06 | The `!CBC` exclusion is causal: a CBC-only client fails against the overlay configuration (0/3, no shared cipher) and succeeds when the list is relaxed to `ALL` (3/3, `ECDHE-RSA-AES256-SHA384`) | `results/handshake_results.json`, variant V6 summary, lines 377-381 (`"successes": 0`) and variant V7 summary, lines 425-429; `results/summary.txt`, lines 20-21; `tls_audit.md`, lines 215-216 |
| M-07 | A TLS 1.1-only client is rejected by the overlay configuration (0/3, protocol-version alert) | `results/handshake_results.json`, variant V8 summary, lines 473-477 (`"successes": 0`); `results/summary.txt`, line 22; `tls_audit.md`, line 217 |
| M-08 | DHE negotiates against the embedded DH parameters: `DHE-RSA-AES256-GCM-SHA384` under TLS 1.2 (1/1, via the `openssl` CLI server) | `results/handshake_results.json`, variant V9 summary, lines 498-502; `results/summary.txt`, line 23; `tls_audit.md`, line 218; `results/cipher_matrix.csv`, line 37 (`DHE-RSA-AES256-GCM-SHA384,1.2,DHE,RSA,AEAD,yes,yes,yes,yes`) |
| M-09 | Setting the overlay cipher string on a TLS 1.3-only server changes nothing: still TLS 1.3, `TLS_AES_256_GCM_SHA384` (3/3) | `results/handshake_results.json`, variant V10 summary, lines 546-550; `results/summary.txt`, line 24; `tls_audit.md`, line 219 |
| M-10 | Overlay cipher list expands to 31 TLS 1.2 suites under local OpenSSL 3.0.13; DEFAULT expands to 27; ALL to 71; TLS 1.3 defaults to 3 suites | `results/handshake_results.json`, `cipher_matrix` fields, lines 31-34 (`overlay_tls12_suite_count` 31, `default_tls12_suite_count` 27, `all_tls12_suite_count` 71, `tls13_suite_count` 3); `results/summary.txt`, lines 6-9; `results/cipher_matrix.csv`, 74 data rows + header (75 lines total) |
| M-11 | 8 RSA key-transport suites remain in the overlay list; 0 CBC suites remain | `results/handshake_results.json`, `overlay_includes_rsa_kx` list, lines 82-91 (8 entries), and `overlay_includes_cbc` line 92 (`[]`); `results/summary.txt`, lines 10-11; `results/cipher_matrix.md`, lines 16 and 20-23 |
| M-12 | Test certificate: RSA 2048-bit, `sha256WithRSAEncryption`, serial `20:26:11:13:00:00:00:00:00:00:00:00:00:00:00:42`, validity 2026-11-12 to 2028-11-12 UTC, SHA-256 fingerprint `2f6c197f20e2d048df32d0d7c4862ff42f741ad9726921ac24701c8f2fa89389`, empty subject/issuer | `results/cert_properties.json`, lines 2-10 (`sha256_fingerprint` line 2, `serial` line 3, `signature_algorithm` line 4, `not_before` line 7, `not_after` line 8, `public_key_bits` line 10); `results/handshake_results.json`, `certificate` block, lines 14-22; `results/summary.txt`, line 12; `tls_audit.md`, lines 262-267 |
| M-13 | Embedded DH parameters are 2048-bit and pass `openssl dhparam -check` | `results/dh_params.txt`, line 1 (`DH Parameters: (2048 bit)`) and line 22 (`DH parameters appear to be ok.`); `results/handshake_results.json`, `dh_parameters` block, lines 25-29 (`bits` 2048, `check_ok` true); `results/summary.txt`, line 13 |
| M-14 | Every variant's attempts agree with each other (no flaky negotiation) | `results/handshake_results.json`, each variant summary's `all_attempts_agree` field (e.g. V1 lines 137-142); `results/summary.txt`, lines 15-24 (all rows show uniform outcomes) |

## Source-derived claims (from the pinned tree and primary sources)

| # | Claim | Evidence |
|---|-------|----------|
| S-01 | The peer overlay uses `make_SSLContext("")` — empty cipher list means the default cipher list | Pinned tree: `src/xrpld/overlay/detail/OverlayImpl.cpp`, line 1550; `src/libxrpl/basics/make_SSLContext.cpp`, lines 361-362 (empty list falls back to `defaultCipherList`). Cited in `tls_audit.md`, line 37 |
| S-02 | Default cipher list as written is `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL` | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, line 104. Cited in `tls_audit.md`, line 125; `results/handshake_results.json`, line 7 |
| S-03 | TLS contexts are created in exactly three production paths (make_SSLContext/make_SSLContextAuthed; bare sslv23 for non-secure ports; tlsv12_client for outbound work) | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp:347`; `src/xrpld/rpc/detail/ServerHandler.cpp`, lines 1090-1098; `src/xrpld/app/misc/detail/WorkSSL.cpp`, lines 36-41. Cited in `tls_audit.md`, lines 11-63 |
| S-04 | SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are disabled; TLS 1.2 and TLS 1.3 are allowed (nothing disables them) | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, lines 352-359 (option flags). Cited in `tls_audit.md`, lines 68-94 |
| S-05 | No minimum/maximum TLS version is set anywhere; no `SSL_CTX_set_ciphersuites` call exists in the tree | Grep over `src/` and `include/` (no matches for `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_ciphersuites`); cited in `tls_audit.md`, lines 90-92 and 143-144 |
| S-06 | `SSL_CTX_set_cipher_list` affects TLS 1.2 and below only; it does not affect TLS 1.3 ciphersuites | OpenSSL documentation, `SSL_CTX_set_cipher_list(3)` (https://docs.openssl.org/master/man3/SSL_CTX_set_cipher_list/); cited in `sources.md` and `tls_audit.md`, lines 137-148 |
| S-07 | The overlay certificate is an ephemeral self-signed RSA-2048 certificate, SHA-256 signature, 2-year validity, empty subject/issuer, 128-bit random serial | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, lines 66 (`defaultRSAKeyBits = 2048`), 112-121 (`RSA_generate_key_ex`), 155 (version 3), 160-172 (validity: yesterday 00:00 UTC + 2 years), 177 (128-bit serial), 233 (`X509_sign` with `EVP_sha256()`). Cited in `tls_audit.md`, lines 237-260 |
| S-08 | No certificate verification on the peer overlay, in either direction | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, line 391 (`verify_none`); `src/xrpld/overlay/detail/ConnectAttempt.cpp`, line 175 (`verify_none`); `include/xrpl/server/detail/SSLHTTPPeer.h`, line 152 (`verify_none`). Cited in `tls_audit.md`, lines 272-277 |
| S-09 | Peer authentication happens above TLS: secp256k1 node key + session signature over a shared value derived from the TLS Finished messages (SHA-512, first half) | Pinned tree: `src/xrpld/overlay/detail/Handshake.cpp`, lines 128 (`hashLastMessage`), 146 (`makeSharedValue`), 148-156 (`SSL_get_finished` / `SSL_get_peer_finished`), 174 (`sha512Half`), 294 (secp256k1-only key type), 304 (two-purposes comment), 311-318 (session signature verification). Cited in `tls_audit.md`, lines 283-305 |
| S-10 | `verifyEndpoints` is peer-finder address validation, not TLS verification | Pinned tree: `src/xrpld/overlay/detail/OverlayImpl.cpp`, line 1566; `src/xrpld/peerfinder/detail/Logic.h`, line 757. Cited in `tls_audit.md`, lines 308-312 |
| S-11 | Embedded DH parameters are 2048-bit, generated with `openssl dhparam 2048` on 29 May 2022 | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, lines 69-80 (comment) and 80-100 (blob), line 369 (`use_tmp_dh`). Measured check: M-13 |
| S-12 | Pinned OpenSSL is 1.1.1w; 1.1.1 public support ended 11 Sep 2023; 1.1.1w was the last release | Pinned tree: `conanfile.py`, line 30; `CMakeLists.txt`, line 88. OpenSSL project, "OpenSSL 1.1.1 End Of Life Approaching", 15 June 2023 (https://openssl-library.org/post/2023-06-15-1.1.1-eol-reminder/). Cited in `tls_audit.md`, lines 341-350; `sources.md` |
| S-13 | OpenSSL 1.1.1 added TLS 1.3 support (so the pinned library can negotiate TLS 1.3) | OpenSSL NEWS.md, "Major changes between OpenSSL 1.1.0i and OpenSSL 1.1.1 [11 Sep 2018]". Cited in `tls_audit.md`, lines 83-88; `sources.md` |
| S-14 | Renegotiation disabled (`SSL_OP_NO_RENEGOTIATION`, citing CVE-2021-3499); compression disabled; single DH use | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, lines 358-359 and 375. Cited in `tls_audit.md`, lines 96-102 |
| S-15 | TLS 1.3 removes RSA key transport and mandates ephemeral (EC)DHE; all 5 RFC 8446 suites are AEAD | RFC 8446 (IETF, Aug 2018). Cited in `sources.md` and `exposure_analysis.md`, lines 15-22 |
| S-16 | Exposure severities are Medium for all three traffic classes (peer-overlay, RPC, outbound work) | `exposure_analysis.md`, summary table, lines 225-227; per-class rationale: Class 1 line 115, Class 2 line 163, Class 3 line 213 |
| S-17 | ML-KEM-768 sizes: encapsulation key 1,184 bytes, decapsulation key 2,400 bytes, ciphertext 1,088 bytes, shared secret 32 bytes; NIST's recommended default | NIST FIPS 203, Table 3 (final, 13 Aug 2024). Cited in `hybrid_migration.md`, lines 64-69; `sources.md` |
| S-18 | `X25519MLKEM768` hybrid group, RFC 10024 (Aug 2026), IANA code point `0x11EC` | RFC 10024. Cited in `hybrid_migration.md`, lines 13-16 and 62-69; `sources.md` |
| S-19 | OpenSSL 3.5 (8 Apr 2025) is the first release with native ML-KEM/ML-DSA/SLH-DSA; 1.1.1w has no ML-KEM and no provider interface to add it | OpenSSL 3.5 final release announcement, 8 Apr 2025 (https://openssl-library.org/post/2025-04-08-openssl-35-final-release). Cited in `hybrid_migration.md`, lines 13-22 (verdict) and 32-50 (blocker); `sources.md` |
| S-20 | Hybrid ML-KEM migration is blocked on the pinned OpenSSL, not on the protocol; first step is the OpenSSL upgrade | `hybrid_migration.md`, lines 13-22 (verdict) and 32-50 (blocker); sequencing in lines 257-270 |
| S-21 | The tree never configures TLS 1.3 groups and never logs negotiated TLS parameters | Grep over `src/` and `include/` (no `SSL_CTX_set1_groups` call); stated in `hybrid_migration.md`, lines 50-60 and open question 5, lines 244-249 |
| S-22 | ML-DSA-65 sizes: public key 1,952 bytes, signature 3,309 bytes | NIST FIPS 204, Table 2. Cited in `hybrid_migration.md`, line 225; `sources.md` |

## What is NOT claimed (limits)

- No claim about which version/suite any live peer connection
  negotiates — only the envelope of possible outcomes, measured
  locally. See `tls_audit.md`, Section 7, and `assumptions.md`.
- No claim about exact cipher-suite counts under the pinned
  1.1.1w — measured under local OpenSSL 3.0.13 only
  (`tls_audit.md`, lines 199-203; `assumptions.md`).
- No claim that the ledger was compiled or executed — it was not
  (`assumptions.md`).
- No claim that a hybrid handshake was run — it was not; the
  migration design is specified against OpenSSL 3.5 behaviour as
  documented (`hybrid_migration.md`, Section 1; `assumptions.md`).

## Reproduction

Run `bash run_all.sh` from a fresh copy of this repository with
`POSTFIATD_TREE` set to a checkout of the pinned commit: it
re-runs the harness, rebuilds `results/cipher_matrix.md` and
`docs/index.html`, regenerates `SHA256SUMS`, and verifies digests.
Expected: exit 0, all derived outputs byte-identical to the shipped
files. See `REPRODUCTION.md` for the exact command and recorded
result. Verify digests at any time with
`bash verify_digests.sh --check`.
