# Harvest-now-decrypt-later exposure analysis

Threat model: a passive adversary records encrypted traffic today
and, at some later date, possesses a cryptographically relevant
quantum computer (CRQC) — one able to run Shor's algorithm against
2048-bit RSA and the elliptic-curve groups in use. The question per
traffic class is: **what does the recording contain, what could the
CRQC decrypt from it, and what stays safe?** All three traffic
classes are grounded in the TLS context paths audited in
`tls_audit.md`; the negotiated-version/cipher facts are measured in
`results/handshake_results.json`.

Two facts shape every rating below:

1. **TLS 1.3 sessions are forward-secret by construction.** RFC 8446
   removed RSA key transport; every TLS 1.3 session uses ephemeral
   (EC)DHE, and the ephemeral keys are discarded when the session
   ends. A later CRQC cannot recover a TLS 1.3 session key from the
   recording alone, because there is no long-term secret in the
   recording that encrypts it. The harness confirms TLS 1.3 is what
   negotiates by default under the overlay configuration (variant
   V1: TLS 1.3, `TLS_AES_256_GCM_SHA384`, 3/3).
2. **TLS 1.2 sessions are forward-secret only if they negotiated
   (EC)DHE.** The overlay cipher list still admits 8 RSA
   key-transport suites, and variant V5 proves one of them
   (`TLS_RSA_WITH_AES_256_GCM_SHA384`) negotiates against the
   overlay configuration. In an RSA key-transport session the
   pre-master secret is encrypted to the server's RSA public key;
   anyone who later obtains the matching private key can decrypt
   the recorded session. The mitigating factor is that the overlay
   RSA key is ephemeral per process start (`tls_audit.md`,
   Section 4.1): it exists only in the server's memory while that
   process runs, and is regenerated at the next start. So a
   harvest-now-decrypt-later attack on an overlay RSA session needs
   **two** successes — the recording, and acquisition of the
   ephemeral private key during the process's lifetime (memory
   disclosure, host compromise, or a key-extraction vulnerability).
   That is a narrower window than a long-lived certificate key, but
   it is not zero, and it is the only HNDL path in the overlay.

What a CRQC does **not** change: symmetric cryptography and hashes
keep most of their strength. Grover's algorithm gives only a
quadratic speedup, so AES-128 drops to ~64 bits of effective
quantum security and AES-256 to ~128 bits; SHA-256/SHA-512
preimage resistance halves similarly. None of the recorded sessions
depends on a 128-bit symmetric key being unbreakable in the
post-quantum sense, and AES-256-GCM (the suite that negotiates by
default) retains ~128-bit quantum security. The exposure is
therefore entirely in the **asymmetric** parts: RSA key transport
and the long-term identity keys.

## Class 1 — Peer-overlay validation traffic

**Code path.** The peer overlay context, `make_SSLContext("")`
(`src/xrpld/overlay/detail/OverlayImpl.cpp:1550`), via
`get_context` / `initAnonymous`
(`src/libxrpl/basics/make_SSLContext.cpp:347`, `:107`). No
certificate verification in either direction
(`make_SSLContext.cpp:391`;
`src/xrpld/overlay/detail/ConnectAttempt.cpp:175`;
`include/xrpl/server/detail/SSLHTTPPeer.h:152`).

**What a passive recorder gets.** TLS records containing the peer
protocol: validations, proposals, transactions and ledger data
exchanged between peers, plus the overlay handshake headers
(node public key, session signature, network ID, ledger hashes).
The node public key and ledger hashes are public by design; the
validations themselves are broadcast publicly across the network.

**What a CRQC could decrypt later.**

- TLS 1.3 sessions (the default outcome): **nothing**. Ephemeral
  (EC)DHE only; no long-term secret in the recording encrypts the
  session keys.
- TLS 1.2 sessions with (EC)DHE (variants V4, V9): **nothing**.
  Same reasoning; the DHE parameters are public and the ephemeral
  shares are discarded.
- TLS 1.2 sessions with RSA key transport (variant V5):
  **everything in that session**, *if* the adversary also obtains
  the server's ephemeral RSA private key while the process that
  generated it is still running. The plaintext is peer-protocol
  traffic — validation messages, proposals, transactions, ledger
  data. Most of that data is public anyway (validations and ledger
  data are broadcast), so the marginal loss from decrypting it is
  small. The exception is anything a peer sends that is not
  otherwise public — peer-specific handshake metadata and any
  non-broadcast payload — and the fact that the recording also
  reveals *which* peers talked to *which*, when, and how much:
  traffic-analysis metadata that TLS never hides, quantum computer
  or not.

**What stays safe.** Ledger data and validations are public
regardless of TLS; decrypting them discloses nothing new. Peer
authentication does not depend on TLS at all: the overlay
handshake binds the session to the peer's secp256k1 node key via a
signature over the TLS Finished-message hash
(`src/xrpld/overlay/detail/Handshake.cpp:146`, `:304`). A CRQC
does not retroactively break that binding for recorded sessions —
but see the forge-later note below. The *confidentiality* of the
session rests on the ephemeral key exchange, not on the RSA
certificate.

**Forge-later note (not HNDL, but adjacent).** The node identity
keys are secp256k1. Shor's algorithm breaks secp256k1, so a CRQC
that obtains a node's public key (public, in every handshake)
could in principle derive the node private key and then
*impersonate* that node in future sessions. That is a
forge-later risk on the identity layer, not a decrypt-later risk
on the transport layer, and it is outside the transport migration
in `hybrid_migration.md` — but any migration plan that secures
the transport and leaves secp256k1 node identities in place has
secured the smaller half of the problem. (The key-lifecycle pack
covers the identity-key side in detail.)

**Severity: Medium.** Rationale: the default negotiation (TLS 1.3)
is safe, and the vulnerable path (TLS 1.2 + RSA key transport)
requires a second, time-limited success (key acquisition during
process lifetime) and mostly exposes already-public data. It is
not Low because the vulnerable configuration is reachable today
with no operator error — a peer offering only RSA suites negotiates
it — and because the overlay's forward secrecy is accidental
(depends on the peer's preference order) rather than enforced.

## Class 2 — RPC traffic (secure ports)

**Code path.** Secure RPC / WebSocket ports use the same context
builder: `make_SSLContext(p.ssl_ciphers)` or
`make_SSLContextAuthed(...)` when operator certificate files are
configured (`src/xrpld/rpc/detail/ServerHandler.cpp:1090-1093`).
Same cipher list default, same version policy, same `verify_none`
posture toward clients.

**What a passive recorder gets.** TLS records containing RPC
requests and responses: account information, ledger queries,
transaction submissions, and — for administrative ports —
potentially sensitive material such as seeds, keys and signing
requests. Unlike peer traffic, RPC payloads are **not** public by
design; their confidentiality is entirely a TLS property.

**What a CRQC could decrypt later.**

- TLS 1.3 sessions: **nothing** (same reasoning as Class 1).
- TLS 1.2 (EC)DHE sessions: **nothing**.
- TLS 1.2 RSA key-transport sessions: **everything in that
  session**, if the adversary also obtains the private key of the
  certificate the RPC port presented. Here the mitigating factor
  from Class 1 is weaker: an operator-supplied certificate
  (`make_SSLContextAuthed`) typically has a **long-lived** private
  key, stored on disk, possibly for years — a much larger window
  for key acquisition than the overlay's per-process ephemeral key.
  The default (no operator files) uses the same ephemeral
  self-signed certificate as the overlay, with the same narrow
  window. Which case applies is operator configuration, not code,
  and is **not determinable statically**.

**What stays safe.** As in Class 1, TLS 1.3 and (EC)DHE TLS 1.2
sessions stay safe. Ledger data returned over RPC is public data
in any case. What does *not* stay safe is the assumption that
"TLS means the RPC payload is safe from future decryption": under
TLS 1.2 with an RSA suite, that assumption holds only while the
server private key holds.

**Severity: Medium.** Rationale: same transport properties as
Class 1, but the plaintext at risk is higher-value (RPC payloads,
possibly seeds and keys) and, in the operator-certificate case,
the key-acquisition window is years rather than one process
lifetime. It is not High because the default negotiation is still
TLS 1.3 and the RSA path still needs the private key; a passive
recorder alone, with a CRQC and nothing else, decrypts nothing.

## Class 3 — Outbound work traffic (WorkSSL)

**Code path.** `src/xrpld/app/misc/detail/WorkSSL.cpp:36-41`:
`HTTPClientSSLContext` with method `tlsv12_client` — **TLS 1.2
only**. Verification is conditional on operator configuration
(`include/xrpl/net/HTTPClientSSLContext.h:100-160`): `verify_peer`
with RFC 2818 hostname checking when `SSL_VERIFY` is enabled,
`verify_none` when it is not.

**What a passive recorder gets.** TLS 1.2 records of outbound
HTTPS requests the node makes to external hosts (work items: data
fetches the node performs as part of its operation). The content
depends on what the node is configured to fetch; it is not ledger
data.

**What a CRQC could decrypt later.**

- There is **no TLS 1.3** on this path, so the mandatory-forward-
  secrecy guarantee of Class 1 and 2 does not apply. Forward
  secrecy depends entirely on the negotiated TLS 1.2 suite.
- The client is `HTTPClientSSLContext`, which does **not** set a
  cipher list at all — the suite selection is the OpenSSL default
  for a `tlsv12_client` context, negotiated with the remote
  server. RSA key-transport suites are therefore possible if the
  remote server selects them (the OpenSSL DEFAULT list includes
  `AES256-GCM-SHA384` and `AES128-GCM-SHA256`, both RSA
  key-transport suites; see `results/cipher_matrix.csv`, lines 4
  and 9). If such a suite negotiates, the recorded session is
  decryptable by anyone who later obtains the **remote server's**
  private key — a key the node operator does not control and cannot
  rotate.
- Additionally, if the operator has verification disabled
  (`verify_none`), an active attacker could already impersonate the
  remote host today — but that is a present-tense
  man-in-the-middle risk, not a harvest-now-decrypt-later one, and
  it depends on operator configuration.

**What stays safe.** (EC)DHE TLS 1.2 sessions stay safe, as in the
other classes. The node's own keys are not involved: the node is
the TLS client here, and its identity is not asserted to the
remote host.

**Severity: Medium.** Rationale: this is the only class with no
TLS 1.3 escape hatch — every session is TLS 1.2 — and the key that
would unlock a recorded RSA session belongs to a third party. It
is not High because the traffic is outbound work data (not ledger
or identity material), the default OpenSSL client preference
order puts ECDHE suites first, and decryption still needs the
remote server's private key.

## Summary table

| Traffic class | Code path | Default negotiation | HNDL-decryptable if... | Severity |
|---|---|---|---|---|
| Peer-overlay validation traffic | `make_SSLContext("")`, overlay | TLS 1.3 | TLS 1.2 + RSA suite **and** ephemeral RSA key obtained during process lifetime | Medium |
| RPC traffic (secure ports) | `make_SSLContext` / `make_SSLContextAuthed` | TLS 1.3 | TLS 1.2 + RSA suite **and** server private key obtained (long-lived if operator-supplied) | Medium |
| Outbound work traffic | `tlsv12_client` (WorkSSL) | TLS 1.2 only | TLS 1.2 + RSA suite **and** remote server private key obtained | Medium |

## What would change the ratings

- **Enforcing TLS 1.3 or (EC)DHE-only TLS 1.2 on the overlay and
  RPC paths** (remove the RSA suites from the cipher list, or set a
  TLS 1.3 minimum) would move Classes 1 and 2 to Low: the only
  remaining HNDL surface would be a TLS implementation flaw, not a
  protocol property. This is a configuration change, not a
  post-quantum one, and it can be made before any ML-KEM work.
- **Moving WorkSSL to TLS 1.3** would move Class 3 to Low for the
  same reason.
- **Hybrid ML-KEM key exchange** (`hybrid_migration.md`) removes
  the quantum half of the RSA key-transport risk entirely, but it
  does not change the ratings on its own for sessions that still
  negotiate classical-only key exchange with a non-forward-secret
  suite. The two changes are complementary: ML-KEM protects the
  key exchange against a CRQC; removing RSA suites protects it
  against a classical key compromise too.
- **Nothing in this analysis depends on ledger data being secret.**
  It is not. The confidentiality at stake is session keys,
  RPC payloads, and traffic metadata — not the ledger.
