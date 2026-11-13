# Cipher-negotiation matrix

Expansion of the cipher-list strings under the local OpenSSL (OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)), recorded in `results/handshake_results.json` under `cipher_matrix`.

Cipher list as written in the code (`src/libxrpl/basics/make_SSLContext.cpp:104`): `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`.

## Counts (TLS 1.2, local OpenSSL)

| List | Suites |
|---|---:|
| Overlay list as written | 31 |
| OpenSSL DEFAULT | 27 |
| ALL | 71 |
| TLS 1.3 defaults (never configured by the code) | 3 |

## What the overlay list contains (TLS 1.2, 31 suites)

- ECDHE suites: 14
- DHE suites: 9
- RSA key-transport suites (no forward secrecy): 8 — AES128-CCM, AES128-CCM8, AES128-GCM-SHA256, AES256-CCM, AES256-CCM8, AES256-GCM-SHA384, ARIA128-GCM-SHA256, ARIA256-GCM-SHA384
- CBC suites: 0

The `!CBC` exclusion removes all 36 CBC suites that `ALL` offers; the `!DSS`, `!PSK`, `!eNULL` and `!aNULL` exclusions remove the DSS, PSK, null-encryption and anonymous suites. What the string does **not** exclude is RSA key transport: 8 RSA suites remain, and variant V5 of the harness negotiates one of them (TLS_RSA_WITH_AES_256_GCM_SHA384).

## TLS 1.3 suites (3, defaults)

The code never calls `SSL_CTX_set_ciphersuites`, so the TLS 1.3 suite list is whatever the linked OpenSSL offers by default. `SSL_CTX_set_cipher_list` does not affect TLS 1.3 ciphersuites (OpenSSL documentation, `SSL_CTX_set_cipher_list(3)`), so the `!CBC` wording has no effect on TLS 1.3 at all — and TLS 1.3 has no CBC suites to exclude in the first place (RFC 8446).

- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

## Full matrix

Same data as `cipher_matrix.csv`. `in_overlay_list` is `n/a` for TLS 1.3 rows: the cipher list does not apply to TLS 1.3 suites.

| Suite | TLS | Key exchange | Auth | Encryption | Forward secrecy | In overlay list |
|---|---|---|---|---|---|---|
| `AES128-CCM` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES128-CCM8` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES128-GCM-SHA256` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES128-SHA` | 1.2 | RSA | RSA | CBC | no | no |
| `AES128-SHA256` | 1.2 | RSA | RSA | CBC | no | no |
| `AES256-CCM` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES256-CCM8` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES256-GCM-SHA384` | 1.2 | RSA | RSA | AEAD | no | yes |
| `AES256-SHA` | 1.2 | RSA | RSA | CBC | no | no |
| `AES256-SHA256` | 1.2 | RSA | RSA | CBC | no | no |
| `ARIA128-GCM-SHA256` | 1.2 | RSA | RSA | AEAD | no | yes |
| `ARIA256-GCM-SHA384` | 1.2 | RSA | RSA | AEAD | no | yes |
| `CAMELLIA128-SHA` | 1.2 | RSA | RSA | CBC | no | no |
| `CAMELLIA128-SHA256` | 1.2 | RSA | RSA | CBC | no | no |
| `CAMELLIA256-SHA` | 1.2 | RSA | RSA | CBC | no | no |
| `CAMELLIA256-SHA256` | 1.2 | RSA | RSA | CBC | no | no |
| `DHE-DSS-AES128-GCM-SHA256` | 1.2 | DHE | DSS | AEAD | yes | no |
| `DHE-DSS-AES128-SHA` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-AES128-SHA256` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-AES256-GCM-SHA384` | 1.2 | DHE | DSS | AEAD | yes | no |
| `DHE-DSS-AES256-SHA` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-AES256-SHA256` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-ARIA128-GCM-SHA256` | 1.2 | DHE | DSS | AEAD | yes | no |
| `DHE-DSS-ARIA256-GCM-SHA384` | 1.2 | DHE | DSS | AEAD | yes | no |
| `DHE-DSS-CAMELLIA128-SHA` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-CAMELLIA128-SHA256` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-CAMELLIA256-SHA` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-DSS-CAMELLIA256-SHA256` | 1.2 | DHE | DSS | CBC | yes | no |
| `DHE-RSA-AES128-CCM` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES128-CCM8` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES128-GCM-SHA256` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES128-SHA` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-AES128-SHA256` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-AES256-CCM` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES256-CCM8` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES256-GCM-SHA384` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-AES256-SHA` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-AES256-SHA256` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-ARIA128-GCM-SHA256` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-ARIA256-GCM-SHA384` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `DHE-RSA-CAMELLIA128-SHA` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-CAMELLIA128-SHA256` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-CAMELLIA256-SHA` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-CAMELLIA256-SHA256` | 1.2 | DHE | RSA | CBC | yes | no |
| `DHE-RSA-CHACHA20-POLY1305` | 1.2 | DHE | RSA | AEAD | yes | yes |
| `ECDHE-ARIA128-GCM-SHA256` | 1.2 | ECDHE | ARIA128 | AEAD | yes | yes |
| `ECDHE-ARIA256-GCM-SHA384` | 1.2 | ECDHE | ARIA256 | AEAD | yes | yes |
| `ECDHE-ECDSA-AES128-CCM` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES128-CCM8` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES128-SHA` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-AES128-SHA256` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-AES256-CCM` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES256-CCM8` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-AES256-SHA` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-AES256-SHA384` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-ARIA128-GCM-SHA256` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-ARIA256-GCM-SHA384` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-ECDSA-CAMELLIA128-SHA256` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-CAMELLIA256-SHA384` | 1.2 | ECDHE | ECDSA | CBC | yes | no |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | 1.2 | ECDHE | ECDSA | AEAD | yes | yes |
| `ECDHE-RSA-AES128-GCM-SHA256` | 1.2 | ECDHE | RSA | AEAD | yes | yes |
| `ECDHE-RSA-AES128-SHA` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-AES128-SHA256` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-AES256-GCM-SHA384` | 1.2 | ECDHE | RSA | AEAD | yes | yes |
| `ECDHE-RSA-AES256-SHA` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-AES256-SHA384` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-CAMELLIA128-SHA256` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-CAMELLIA256-SHA384` | 1.2 | ECDHE | RSA | CBC | yes | no |
| `ECDHE-RSA-CHACHA20-POLY1305` | 1.2 | ECDHE | RSA | AEAD | yes | yes |
| `TLS_AES_128_GCM_SHA256` | 1.3 | (EC)DHE (ephemeral, per RFC 8446) | certificate (any) | AEAD | yes | n/a (cipher list does not apply to TLS 1.3) |
| `TLS_AES_256_GCM_SHA384` | 1.3 | (EC)DHE (ephemeral, per RFC 8446) | certificate (any) | AEAD | yes | n/a (cipher list does not apply to TLS 1.3) |
| `TLS_CHACHA20_POLY1305_SHA256` | 1.3 | (EC)DHE (ephemeral, per RFC 8446) | certificate (any) | AEAD | yes | n/a (cipher list does not apply to TLS 1.3) |

Notes

- ECDSA-authenticated suites (`ECDHE-ECDSA-*`) are listed by the cipher string but cannot negotiate against the overlay's RSA certificate: the server has no ECDSA key. They are in the list, not on the wire.
- Suite counts depend on the linked OpenSSL version: the pinned library is 1.1.1w, the harness ran against local OpenSSL 3.0.13. The *shape* of the finding (RSA key transport still permitted, CBC excluded, TLS 1.3 untouched) follows from the cipher string and the OpenSSL API, not from the version.
