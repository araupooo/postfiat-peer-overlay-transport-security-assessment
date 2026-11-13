# TLS configuration audit — postfiatd peer overlay

Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. All file:line citations
are against that tree. Companion measurements (what actually
negotiates under this configuration) are in
`results/handshake_results.json`, `results/cipher_matrix.csv` and
`results/cipher_matrix.md`; the harness that produced them is
`harness.py`.

## 1. The three TLS context creation paths

The tree creates TLS contexts in exactly three production paths. The
peer overlay uses the first.

### Path A — `make_SSLContext` / `make_SSLContextAuthed` (peer overlay + secure RPC)

`src/libxrpl/basics/make_SSLContext.cpp`. Both functions funnel
through `get_context` (`make_SSLContext.cpp:347`), then differ only
in how the certificate is supplied:

- `make_SSLContext(cipherList)` (`make_SSLContext.cpp:385`):
  builds the context, then calls `initAnonymous` (line 388), which
  installs an ephemeral self-signed certificate (Section 3), and sets
  `verify_none` (line 391).
- `make_SSLContextAuthed(keyFile, certFile, chainFile, cipherList)`
  (`make_SSLContext.cpp:396`): builds the context, then calls
  `initAuthenticated` (line 249), which loads an operator-supplied
  certificate, chain and private key from files and checks that the
  key matches the certificate (`SSL_CTX_check_private_key`,
  `make_SSLContext.cpp:340`).

Callers:

| Caller | Call | Context used for |
|---|---|---|
| `src/xrpld/overlay/detail/OverlayImpl.cpp:1550` | `make_SSLContext("")` | The peer overlay (all peer connections, inbound and outbound). Empty string means "use the default cipher list" (`make_SSLContext.cpp:361-362`). |
| `src/xrpld/rpc/detail/ServerHandler.cpp:1090` | `make_SSLContext(p.ssl_ciphers)` | Secure RPC / WebSocket ports with no operator certificate files configured. |
| `src/xrpld/rpc/detail/ServerHandler.cpp:1092-1093` | `make_SSLContextAuthed(...)` | Secure RPC / WebSocket ports with operator certificate files configured. |

### Path B — bare `sslv23` context (non-secure RPC ports)

`src/xrpld/rpc/detail/ServerHandler.cpp:1097-1098`: for a port that
is not secure, the code still creates a
`boost::asio::ssl::context` with method `sslv23`, but never configures
it — no cipher list, no certificate, no options. It exists so the
port object always has a context; it is not used to negotiate TLS on
a plaintext port. No TLS claim in this pack rests on it.

### Path C — `tlsv12_client` (outbound work traffic)

`src/xrpld/app/misc/detail/WorkSSL.cpp:36-41`: outbound HTTPS work
uses `HTTPClientSSLContext` with method
`boost::asio::ssl::context::tlsv12_client` — TLS 1.2 only, client
role. Certificate verification is conditional: `preConnectVerify`
sets `verify_none` when the operator has verification disabled, and
`postConnectVerify` sets `verify_peer` with an RFC 2818 hostname
check when verification is enabled
(`include/xrpl/net/HTTPClientSSLContext.h:100-160`). The verify
material (CA file / directory) comes from the operator's
`SSL_VERIFY`, `SSL_VERIFY_FILE` and `SSL_VERIFY_DIR` configuration
(`WorkSSL.cpp:37-39`). Whether verification is on therefore depends
on operator configuration, not on the code — see Section 6.

## 2. Protocol versions: what the code sets

`get_context` (`make_SSLContext.cpp:347-377`) creates the context
with method `boost::asio::ssl::context::sslv23` (line 350) and sets
these options (lines 352-359):

```
default_workarounds | no_sslv2 | no_sslv3 | no_tlsv1 | no_tlsv1_1 |
single_dh_use | no_compression
```

What that means, item by item:

- **SSLv2, SSLv3, TLS 1.0, TLS 1.1 are disabled.** Each is named
  explicitly. Harness variant V8 confirms the effect: a TLS 1.1
  client is rejected with a protocol-version alert
  (`results/handshake_results.json`, variant V8, 0/3 succeeded).
- **TLS 1.2 and TLS 1.3 are both allowed.** Nothing disables them.
  `sslv23` is the generic TLS method: the handshake negotiates the
  highest version both ends support. The pinned OpenSSL, 1.1.1w,
  supports TLS 1.3 (TLS 1.3 support was added in OpenSSL 1.1.1;
  OpenSSL NEWS, "Major changes between OpenSSL 1.1.0i and OpenSSL
  1.1.1"). Harness variant V1 confirms the effect: the overlay
  configuration as written negotiates **TLS 1.3**
  (`TLS_AES_256_GCM_SHA384`, 3/3 attempts).
- **No minimum/maximum version is set anywhere else.** There is no
  `set_min_proto_version` / `SSL_CTX_set_min_proto_version` call in
  the tree (checked by grep across `src/` and `include/`). The
  option flags above are the entire version policy for paths A and
  B. For path C the version is pinned by the `tlsv12_client` method
  itself: TLS 1.2 only, no TLS 1.3.
- **Compression is disabled** (`no_compression`, line 359). TLS
  compression is also absent from TLS 1.3 by design (RFC 8446).
- **Renegotiation is disabled**: `SSL_CTX_set_options(...,
  SSL_OP_NO_RENEGOTIATION)` (line 375), with a comment citing
  CVE-2021-3499 for OpenSSL versions before 1.1.1k. Note this only
  affects TLS 1.2; TLS 1.3 has no renegotiation.
- **Single DH use**: `single_dh_use` (line 358) generates a fresh DH
  key per DHE handshake instead of reusing one.

What the code does **not** set:

- No explicit minimum or maximum TLS version (see above).
- No `SSL_OP_CIPHER_SERVER_PREFERENCE`: by default the **client's**
  cipher preference wins. Which TLS 1.2 suite negotiates therefore
  depends on the peer's offered list, not only on this code.
- No session-ticket, session-cache or 0-RTT configuration. TLS 1.3
  session resumption behaviour is whatever the linked OpenSSL does
  by default. Whether any given peer connection resumes a session is
  **not determinable statically**; the harness always performs full
  handshakes and records that.
- No ALPN configuration. No SNI handling on the server side.

## 3. Cipher suites: what the code sets

### 3.1 The cipher list string

`make_SSLContext.cpp:104`:

```
std::string const defaultCipherList = "TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL";
```

The comment above it (lines 92-102) states the intent: TLS 1.2
suites, excluding DSS suites, pre-shared-key suites, suites without
encryption, and suites without authentication. An operator may
override the list globally or per port with the `ssl_ciphers`
directive (`make_SSLContext.cpp:100-102`;
`src/libxrpl/server/Port.cpp:325`; `ServerHandler.cpp:1090`).
An empty cipher-list argument falls back to this default
(`make_SSLContext.cpp:361-362`) — which is exactly what the overlay
does, since it passes `""`.

The string is applied with `SSL_CTX_set_cipher_list`
(`make_SSLContext.cpp:365`). Per the OpenSSL documentation
(`SSL_CTX_set_cipher_list(3)`), that function **sets the list of
available ciphers for TLS 1.2 and below only** and **does not affect
TLS 1.3 ciphersuites**; TLS 1.3 suites are configured separately with
`SSL_CTX_set_ciphersuites`. The tree never calls
`SSL_CTX_set_ciphersuites` (checked by grep across `src/` and
`include/`). Consequences:

1. The `!CBC` / `!DSS` / `!PSK` / `!eNULL` / `!aNULL` exclusions
   apply **only to TLS 1.2** sessions.
2. TLS 1.3 suites are whatever the linked OpenSSL offers by default.
   Under the local OpenSSL 3.0.13 that is 3 suites
   (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`,
   `TLS_AES_128_GCM_SHA256`); RFC 8446 defines 5, the two CCM
   suites are not offered by this build. Harness variant V10
   confirms the code's cipher string is inert for TLS 1.3: setting
   it on a TLS 1.3-only server still negotiates
   `TLS_AES_256_GCM_SHA384`.
3. The `TLSv1.2:` prefix in the string is a cipher-string keyword
   restricting the list to TLS 1.2 suites; it is not a version floor
   (the version floor comes from the option flags in Section 2).

### 3.2 What the list expands to

Measured with the local OpenSSL 3.0.13 (`openssl ciphers -s`); full
data in `results/cipher_matrix.csv`, readable form in
`results/cipher_matrix.md`:

| List | TLS 1.2 suites |
|---|---:|
| Overlay list as written | 31 |
| OpenSSL DEFAULT | 27 |
| ALL | 71 |

Composition of the 31 overlay suites:

- ECDHE suites: 14 (including `ECDHE-RSA-AES256-GCM-SHA384`,
  `ECDHE-RSA-CHACHA20-POLY1305`, and the ECDSA-authenticated
  variants, which cannot negotiate against an RSA certificate —
  see below).
- DHE suites: 9 (including `DHE-RSA-AES256-GCM-SHA384`).
- **RSA key-transport suites: 8** — `AES256-GCM-SHA384`,
  `AES256-CCM8`, `AES256-CCM`, `ARIA256-GCM-SHA384`,
  `AES128-GCM-SHA256`, `AES128-CCM8`, `AES128-CCM`,
  `ARIA128-GCM-SHA256`. These have **no forward secrecy**: the
  client encrypts the pre-master secret to the server's RSA public
  key. The cipher string does not exclude them, because they are
  not CBC, DSS, PSK, null-encryption or anonymous suites.
- CBC suites: **0**. The `!CBC` exclusion removes all 36 CBC suites
  that `ALL` offers (harness variant V6/V7 pair: a CBC-only client
  fails against the overlay configuration and succeeds when the
  list is relaxed to `ALL`).

Two subtleties worth stating plainly:

- The `ECDHE-ECDSA-*` suites are in the list but unreachable in
  practice for the overlay: the server presents an RSA certificate
  and holds no ECDSA key, so an ECDSA-authenticated suite cannot
  complete. They are in the list, not on the wire.
- Suite counts depend on the linked OpenSSL version. The pinned
  library is 1.1.1w; the harness ran against local OpenSSL 3.0.13.
  The *shape* of the finding (RSA key transport still permitted,
  CBC excluded, TLS 1.3 untouched) follows from the cipher string
  and the OpenSSL API, not from the version. Exact counts under
  1.1.1w were **not** measured — no 1.1.1w build is available on
  this machine — and are recorded here as not verified.

### 3.3 What actually negotiates (harness)

| Variant | Configuration | Negotiated |
|---|---|---|
| V1 overlay-as-written | Overlay config, both ends | TLS 1.3, `TLS_AES_256_GCM_SHA384` (3/3) |
| V2 tls13-only | TLS 1.3 only | TLS 1.3, `TLS_AES_256_GCM_SHA384` (3/3) |
| V3 relaxed-tls12 | TLS 1.2, cipher list `ALL` | TLS 1.2, `ECDHE-RSA-AES256-GCM-SHA384` (3/3) |
| V4 overlay-tls12-only | TLS 1.2, overlay list | TLS 1.2, `ECDHE-RSA-AES256-GCM-SHA384` (3/3) |
| V5 rsa-key-transport-tls12 | Overlay server; client offers only `AES256-GCM-SHA384` | TLS 1.2, `AES256-GCM-SHA384` = `TLS_RSA_WITH_AES_256_GCM_SHA384` (3/3) |
| V6 cbc-blocked-by-overlay | Overlay server; client offers only CBC `ECDHE-RSA-AES256-SHA384` | Handshake failure, no shared cipher (0/3) |
| V7 cbc-allowed-when-relaxed | Relaxed server; same CBC-only client | TLS 1.2, `ECDHE-RSA-AES256-SHA384` (3/3) |
| V8 tls11-rejected | Overlay server; TLS 1.1-only client | Handshake failure, protocol version (0/3) |
| V9 tls12-dhe-embedded-params | Overlay list; DHE-only client; server with embedded DH params | TLS 1.2, `DHE-RSA-AES256-GCM-SHA384` (1/1) |
| V10 tls13-ciphersuites-unrestricted | TLS 1.3 only; overlay cipher string set on server | TLS 1.3, `TLS_AES_256_GCM_SHA384` (3/3) |

The single most consequential row is V5: the overlay configuration
**permits non-forward-secret RSA key transport under TLS 1.2**. A
peer that offers only an RSA suite — or a peer whose preference
order puts one first, since the server honors client preference —
negotiates it. This is a property of the cipher string as written,
not of any particular peer.

## 4. Certificates: generation and validation

### 4.1 Generation (path A, anonymous)

`initAnonymous` (`make_SSLContext.cpp:107-245`) generates one RSA
key and one self-signed certificate per process, cached in function
`static` variables (lines 112-145), i.e. generated once at first
use and reused for the life of the process:

- Key: `defaultRSAKeyBits = 2048` (line 66),
  `RSA_generate_key_ex` with exponent `RSA_F4` (65537)
  (lines 112-121). A comment (lines 51-65) justifies 2048 bits by
  citing NIST SP 800-57 Part 3 and by the fact that the key is
  regenerated at every server start.
- Certificate: version 3 (`X509_set_version(x509, 2)`, line 155);
  **no subject or issuer name is set anywhere** — the certificate
  has an empty subject and an empty issuer; serial number is a
  128-bit random value (`BN_rand(b, 128, ...)`, line 177);
  validity starts at yesterday 00:00:00 UTC
  (`std::time(nullptr) - 25h`, formatted `%y%m%d000000Z`,
  lines 160-168) and runs for two years
  (`X509_gmtime_adj(..., 2 * 365 * 24 * 60 * 60)`, line 172);
  signed with `X509_sign(x509, key, EVP_sha256())` (line 233).
- Extensions (lines 190-228): `basicConstraints` critical
  `CA:FALSE`; `extKeyUsage` critical `serverAuth,clientAuth`;
  `keyUsage` critical `digitalSignature`;
  `subjectKeyIdentifier` "hash" (SHA-1 hash of the public key).
- The certificate and private key are installed with
  `SSL_CTX_use_certificate` / `SSL_CTX_use_PrivateKey`
  (lines 237-244).

The harness reproduces this certificate byte-for-byte in structure
(deterministic key from a fixed seed, fixed serial, fixed validity
window; see `harness.py`). Measured properties of the generated test
certificate are in `results/cert_properties.json`: RSA 2048-bit,
`sha256WithRSAEncryption`, serial
`20:26:11:13:00:00:00:00:00:00:00:00:00:00:00:42`, validity
2026-11-12 to 2028-11-12 UTC, SHA-256 fingerprint
`2f6c197f20e2d048df32d0d7c4862ff42f741ad9726921ac24701c8f2fa89389`,
empty subject/issuer, all four extensions present.

### 4.2 Validation — there is none, on the peer overlay

- Server side (inbound peer connections): `make_SSLContext` sets
  `verify_none` (`make_SSLContext.cpp:391`). The inbound handler
  (`include/xrpl/server/detail/SSLHTTPPeer.h:152`) also sets
  `verify_none` on the stream.
- Client side (outbound peer connections):
  `src/xrpld/overlay/detail/ConnectAttempt.cpp:175` sets
  `verify_none` before the handshake.
- The header comment on `make_SSLContext`
  (`include/xrpl/basics/make_SSLContext.h:33`) still reads
  "Create a self-signed SSL context that allows anonymous Diffie
  Hellman" — stale wording from when the context had no
  certificate; the code now installs a certificate, but the
  *validation* posture is unchanged: no peer certificate is ever
  checked.

Consequences:

- **TLS on the peer overlay provides encryption only, not peer
  authentication.** Anybody can complete a TLS handshake with any
  peer; the certificate is self-signed, ephemeral, and unverified.
- Peer authentication happens **above TLS**, in the overlay
  handshake (`src/xrpld/overlay/detail/Handshake.cpp`):
  each peer presents its long-term node public key (secp256k1 only
  — `Handshake.cpp:294` rejects other key types) and a
  `Session-Signature` over a shared value (lines 311-318). The
  shared value is derived from the TLS channel itself:
  `makeSharedValue` (line 146) hashes the local and peer TLS
  Finished messages (`SSL_get_finished` /
  `SSL_get_peer_finished`, lines 148-156) with SHA-512 — see
  `hashLastMessage`, line 128, which requires at least 12 bytes of
  Finished message — and takes the first half (`sha512Half`,
  line 174). The comment at line 304 states the two purposes: it
  proves the peer holds the node private key, and it proves the TLS
  session is end-to-end with that node rather than through a proxy
  running two separate sessions. This is a channel binding, not a
  TLS feature — and it is the only thing stopping a
  man-in-the-middle from sitting between two peers' TLS sessions.
- `verifyEndpoints` (`OverlayImpl.cpp:1566`, default `true`,
  `src/xrpld/overlay/Overlay.h:76`) is **not** TLS verification: it
  controls whether the peer finder discards gossip endpoints with
  invalid addresses (`src/xrpld/peerfinder/detail/Logic.h:757`).
  Disabling it logs a warning (`OverlayImpl.cpp:1567-1570`) but
  changes nothing about TLS.
- For secure RPC ports using `make_SSLContextAuthed`, the server
  presents an operator-supplied certificate, but the *server* still
  does not verify *client* certificates: `make_SSLContextAuthed`
  never calls `set_verify_mode`, and the context-level default from
  `get_context` is not `verify_peer` — so client-certificate
  authentication is not offered on RPC ports either. (Whether the
  RPC *client* — e.g. a wallet — verifies the server certificate
  depends on that client, not on this code.)
- Path C (WorkSSL) is the only path that ever verifies a peer
  certificate, and only when the operator enables it (Section 1).

### 4.3 DH parameters

`get_context` installs temporary DH parameters with
`c->use_tmp_dh(...)` (`make_SSLContext.cpp:369`) from the embedded
`defaultDH` blob (lines 80-100), generated with
`openssl dhparam 2048` on 29 May 2022 per the comment (lines 69-79).
The harness extracts that blob and checks it:
`results/dh_params.txt` — **2048-bit, "DH parameters appear to be
ok."** Variant V9 negotiates `DHE-RSA-AES256-GCM-SHA384` against a
server loaded with exactly those parameters. Note the parameters
are shared by every node running this code (they are compiled in),
which is standard practice for TLS DH parameters but means the
parameters are not per-node secrets — they are not meant to be.

## 5. The pinned OpenSSL

`conanfile.py:30` pins `openssl/1.1.1w`; `CMakeLists.txt:88`
requires `find_package(OpenSSL 1.1.1 REQUIRED)`. OpenSSL 1.1.1
reached public end of life on **11 September 2023** (OpenSSL
project, "OpenSSL 1.1.1 End Of Life Approaching", 15 June 2023);
1.1.1w (12 September 2023) was the last release. Public security
fixes stopped on that date; only a paid premium-support contract
extends them. The tree therefore runs its entire TLS stack on a
library that has received no public security fix for over three
years at the time of writing (November 2026). Any vulnerability
found in 1.1.1w after September 2023 is unpatched in the pinned
build unless the operator rebuilds against a newer OpenSSL — which
the Conan pin prevents without a tree change.

## 6. What the code sets vs what is left to defaults

| Item | Set by the code | Left to OpenSSL defaults |
|---|---|---|
| Disabled versions | SSLv2, SSLv3, TLS 1.0, TLS 1.1 (option flags) | — |
| Allowed versions | TLS 1.2, TLS 1.3 (by omission) | TLS 1.3 suite list; session resumption; 0-RTT |
| TLS 1.2 cipher list | `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL` (or operator `ssl_ciphers`) | — |
| TLS 1.3 ciphersuites | — (never configured) | Full default list |
| Cipher preference | — (not set) | Client preference wins |
| Certificate (overlay) | Ephemeral self-signed RSA-2048, SHA-256, 2-year validity | — |
| Certificate (RPC, authed) | Operator files | — |
| Certificate verification (overlay) | `verify_none`, both directions | — |
| Certificate verification (WorkSSL) | Conditional on operator `SSL_VERIFY` config | CA paths when enabled |
| DH parameters | Embedded 2048-bit `defaultDH` | — |
| Compression | Disabled | — |
| Renegotiation | Disabled (`SSL_OP_NO_RENEGOTIATION`) | — |
| ALPN / SNI (server) | — (not configured) | None offered |

## 7. What cannot be determined statically

- **Which TLS version and suite a given live peer connection
  negotiates.** It depends on the remote peer's offered versions
  and cipher preference order. The harness shows the envelope of
  possible outcomes, not a measurement of any live connection.
- **Whether a given operator overrides the cipher list** with
  `ssl_ciphers`, or supplies their own RPC certificate. Both are
  configuration, not code.
- **Whether WorkSSL verifies certificates in a given deployment.**
  It depends on the operator's `SSL_VERIFY` configuration.
- **Session resumption / 0-RTT behaviour in production.** Not
  configured by the code; depends on OpenSSL defaults and peer
  behaviour. TLS 1.3 0-RTT early data is not used by the overlay
  protocol (the overlay handshake happens after the TLS handshake),
  but that is an inference from the handshake order, not a
  configuration fact.
- **Exact TLS 1.2 suite counts under the pinned 1.1.1w.** Measured
  under local OpenSSL 3.0.13 only; see Section 3.2.
- **Whether the ephemeral RSA private key is erased from memory
  at process exit or on key rotation.** The key is a process-lifetime
  `static`; the code contains no explicit erasure. Memory hygiene
  is not observable statically.
