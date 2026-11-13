# Hybrid ML-KEM transport migration design

How ML-KEM (hybrid with classical ECDHE) could be negotiated for
peer connections in the postfiatd tree at commit `0085a1ff`, what
has to change first, how fallback and rollback work, and what is
still open. This is a design document: no code in the pinned tree
was changed, no hybrid handshake was run against the ledger, and
the local harness does not implement ML-KEM (the VM's OpenSSL
3.0.13 has no ML-KEM support either — see Section 1).

## 0. Verdict in one paragraph

Hybrid ML-KEM for the peer overlay is **feasible but blocked on the
pinned OpenSSL**. The protocol piece already exists as a standard:
TLS 1.3 hybrid key exchange with `X25519MLKEM768` (RFC 10024,
August 2026; IANA code point `0x11EC`), and the implementation
piece already exists in a shipping library: OpenSSL 3.5 (8 April
2025) implements ML-KEM natively and offers the hybrid groups by
default. The pinned library, OpenSSL 1.1.1w, implements neither —
it has no ML-KEM, no ML-DSA, no SLH-DSA, and no provider interface
that could add them without an external library. The first
migration step is therefore not cryptographic at all: it is the
OpenSSL upgrade (1.1.1w → 3.5 LTS, supported to 8 April 2030),
including the Conan pin (`conanfile.py:30`) and the
`find_package(OpenSSL 1.1.1 REQUIRED)` floor
(`CMakeLists.txt:88`). Until that lands, no ML-KEM handshake is
possible in this tree by configuration alone. (The low-level RSA
API used in `initAnonymous` is deprecated in OpenSSL 3.0 and will
need migration to EVP as part of the upgrade; that is a separate,
larger work item and is not scoped here.)

## 1. The blocker, verified

- **Pinned OpenSSL 1.1.1w cannot support ML-KEM.** ML-KEM is
  specified in NIST FIPS 203 (final, 13 August 2024). OpenSSL
  added native support for ML-KEM, ML-DSA and SLH-DSA in version
  3.5, released 8 April 2025 (OpenSSL 3.5 final release
  announcement). Before 3.5 the only path was the external
  OQS provider from the Open Quantum Safe project, plugged in
  through the provider interface — an interface 1.1.1 does not
  have (providers were introduced in OpenSSL 3.0). There is no
  backport path: 1.1.1 has been out of public support since
  11 September 2023.
- **The local harness OpenSSL (3.0.13) cannot support it either.**
  3.0.x predates native ML-KEM; the OQS provider was not installed
  for this pack and is not used. This is why the harness measures
  classical negotiation only, and why the migration design below
  is specified against OpenSSL 3.5 behaviour as documented, not
  measured here. The gap is recorded, not papered over.
- **The pinned tree also cannot express a hybrid group today.**
  The code never configures TLS 1.3 groups at all: there is no
  `SSL_CTX_set1_groups` / `SSL_CTX_set1_groups_list` call in the
  tree, and no `SSL_CTX_set_ciphersuites` call. Group selection is
  entirely the linked OpenSSL's default. That is convenient for
  migration in one respect — upgrading OpenSSL to 3.5 changes the
  *default* group list to include and prefer `X25519MLKEM768` —
  but it also means the tree currently exercises no control over
  which key-exchange groups its peers negotiate, and a deliberate
  migration should add that control rather than rely on a
  library default silently changing under it.

## 2. The target: what a hybrid peer handshake looks like

**Parameter set: ML-KEM-768, hybrid with X25519
(`X25519MLKEM768`).** Sizes from FIPS 203, Table 3: ML-KEM-768
encapsulation key 1,184 bytes, decapsulation key 2,400 bytes,
ciphertext 1,088 bytes, shared secret 32 bytes. The hybrid
key share on the wire is 1,216 bytes (1,184 + 32 for X25519).
ML-KEM-768 is NIST's recommended default and the set the TLS
hybrid groups standardise on; ML-KEM-512 (800 / 768 bytes) and
ML-KEM-1024 (1,568 / 1,568 bytes) exist but are not the TLS
default. Rationale for the hybrid rather than pure ML-KEM: the
session key is derived from *both* exchanges, so the connection
stays secure if either the classical or the post-quantum half
holds — the conservative choice while ML-KEM has a shorter
cryptanalytic history than X25519. The hybrid group is specified
in RFC 10024 ("Post-Quantum Traditional (PQ/T) Hybrid Key
Agreement Mechanisms for TLS 1.3", Standards Track, August 2026).

**Where it applies: TLS 1.3 only.** Hybrid KEM groups are a TLS
1.3 mechanism (the `supported_groups` / `key_share` extensions).
TLS 1.2 has no equivalent standardised hybrid key exchange for
this stack. That aligns with the overlay's actual behaviour: the
overlay already negotiates TLS 1.3 by default (harness variant
V1). The migration therefore does not need to change the version
policy to reach the hybrid — it needs to change the *group* policy
within TLS 1.3.

**What changes in the code (minimal sketch):**

1. Upgrade the OpenSSL dependency to 3.5 LTS: `conanfile.py:30`
   (`openssl/1.1.1w` → `openssl/3.5.x`), `CMakeLists.txt:88`
   (`find_package(OpenSSL 1.1.1 REQUIRED)` → 3.5 floor), and
   re-verify the rest of the tree builds against the 3.x API
   (the low-level RSA API used in `initAnonymous` is deprecated
   in 3.0, and a build configured with `no-deprecated` would fail
   on it — it needs migration to EVP; that is a separate, larger
   work item and is not scoped here).
2. In `get_context` (`src/libxrpl/basics/make_SSLContext.cpp:347`),
   after the existing option flags, set the TLS 1.3 group list
   explicitly instead of relying on the library default, e.g.
   `SSL_CTX_set1_groups_list(ctx,
   "X25519MLKEM768:X25519:secp256r1")` — hybrid first, classical
   fallback second. The exact API is `SSL_CTX_set1_groups_list`
   (OpenSSL 1.1.1+; present in 3.5).
3. Optionally set the TLS 1.3 ciphersuites explicitly with
   `SSL_CTX_set_ciphersuites` (the code never does today); the
   default list is already the AEAD suites and needs no change.
4. No change to the certificate: the RSA-2048 self-signed
   certificate authenticates the handshake (signature only) and
   is not involved in key exchange under TLS 1.3. The hybrid
   change touches key agreement, not authentication. (Replacing
   the RSA certificate with a post-quantum signature is a
   different migration — ML-DSA in certificates — and is out of
   scope here; see Section 5.)
5. No change to the overlay handshake above TLS: the
   `Session-Signature` channel binding
   (`src/xrpld/overlay/detail/Handshake.cpp:146`) works over any
   TLS session, including a hybrid one, because it hashes the
   Finished messages, which exist in every TLS 1.3 handshake.

**Handshake size cost.** A hybrid ClientHello carries an extra
~1,216 bytes of key share (plus a second key share for the
classical fallback if the client offers both, as OpenSSL 3.5 does
by default). Against a peer overlay where connections are
long-lived and infrequent, this is negligible. It matters only if
the tree ever does high-rate short-lived TLS handshakes, which
the overlay does not.

## 3. Negotiation, fallback and mixed networks

**How negotiation works (TLS 1.3, standard).** The client offers
its supported groups in `supported_groups` and sends key shares
for its preferred groups. A server that supports `X25519MLKEM768`
selects it; a server that does not ignores the unknown group and
selects a classical group the client also offered (e.g. X25519).
There is no version-style downgrade attack surface specific to
the hybrid: the server's choice is authenticated by the handshake
signature and the transcript hash, as with any TLS 1.3 group
negotiation. A network attacker cannot force a hybrid-capable
pair down to classical-only without breaking the handshake
authentication — that is the same guarantee TLS 1.3 gives for any
group.

**Fallback rule (recommended).** Offer hybrid first, classical
second; accept whatever the peer selects; **log the negotiated
group** per connection (the tree currently logs no negotiated TLS
parameters at all — adding a log line with version, suite and
group at handshake completion is a precondition for operating
this migration, otherwise nobody can tell whether the fleet is
actually hybrid). Do not fail a connection solely because the peer
is classical-only during the migration window: the overlay is a
peer-to-peer network, and refusing classical peers would partition
the network. The security property during the window is: sessions
with hybrid peers are protected against harvest-now-decrypt-later;
sessions with classical-only peers have exactly today's exposure
(see `exposure_analysis.md`).

**Mixed-network operation.** Because negotiation is per-connection
and the fallback is automatic, a mixed fleet (some nodes on the
new build, some on the old) keeps working with no flag day. The
old nodes simply never offer the hybrid group and keep negotiating
classical ECDHE. The only operational requirement is that the new
build's group list keeps a classical group the old build offers
(X25519 / secp256r1), which the list in Section 2 does.

**When to stop offering classical-only.** Once the fleet is
overwhelmingly hybrid (measured from the per-connection logs, not
assumed), the group list can drop the classical fallback. That
decision needs a measured threshold (e.g. >95% of peer connections
hybrid over a 30-day window) and a rollback plan (Section 4). It
is not part of the first migration step, and this pack does not
recommend a date for it.

## 4. Rollback procedure

Rollback is at the group-list level, not the binary level:

1. **Immediate rollback (no rebuild):** if the group list is set
   from configuration (recommended — add a config knob for it,
   mirroring the existing `ssl_ciphers` directive), revert the
   config value to the classical-only list and restart the node.
   Existing connections are unaffected; new connections negotiate
   classical.
2. **Binary rollback:** if the OpenSSL 3.5 upgrade itself causes
   a problem, rebuild against the previous pinned OpenSSL and
   redeploy. This is the ordinary release rollback; the TLS
   configuration is unchanged by it.
3. **Interoperability rollback:** if a specific peer
   implementation fails on the hybrid ClientHello (e.g. a
   middlebox or an old peer that mishandles the larger key share),
   restrict that peer to classical groups via the per-connection
   fallback — the server already does this automatically by
   selecting a classical group when the client does not offer the
   hybrid one. No operator action is needed for the common case.
4. **Rollback criterion:** any reproducible handshake failure
   attributable to the hybrid group, or any measured regression in
   peer-connection success rate after the rollout, triggers step 1
   first; the investigation happens after the fleet is back on
   classical groups.

What rollback does **not** do: it does not un-record traffic.
Sessions that were hybrid stay protected; sessions that fall back
to classical-only have today's exposure. Rollback is a
forward-looking availability measure, not a retroactive security
measure — which is precisely why the hybrid should be rolled out
early, before a CRQC exists, rather than after one is announced.

## 5. Open questions

1. **OpenSSL 3.5 upgrade scope.** How much of the tree breaks
   against OpenSSL 3.x? `initAnonymous` uses the low-level RSA
   API (`RSA_new`, `RSA_generate_key_ex`, `EVP_PKEY_assign_RSA`
   — `make_SSLContext.cpp:112-140`), deprecated in 3.0. The upgrade
   needs an EVP rewrite of that function and a full build + test
   pass. This pack does not attempt it (a local build of the ledger
   is not feasible on this machine) and does not estimate its size
   beyond "larger than the TLS group change itself".
2. **ML-DSA for peer authentication?** The overlay's peer identity
   is a secp256k1 node key, signed over the Finished-message hash.
   A CRQC breaks secp256k1, so transport hybridisation alone does
   not protect peer identity (forge-later). Replacing or
   supplementing node-key signatures with ML-DSA is a protocol
   change to the overlay handshake, not a TLS change, and needs
   its own design (key sizes: ML-DSA-65 public key 1,952 bytes,
   signature 3,309 bytes — FIPS 204, Table 2; the handshake
   headers would grow accordingly, and old nodes would need to
   verify the new signature type). Out of scope for this document;
   recorded here so the transport migration is not mistaken for a
   complete post-quantum migration.
3. **TLS 1.2 RSA key-transport suites.** The hybrid migration does
   not remove them. Should the cipher list drop RSA suites at the
   same time (making TLS 1.2 forward-secret by construction)? The
   exposure analysis (`exposure_analysis.md`, "What would change
   the ratings") recommends it as a separate, classical-only
   hardening step. It can ship before, with, or after the hybrid
   change; bundling it into the hybrid release conflates two
   changes with different rollback stories.
4. **WorkSSL (TLS 1.2-only client).** The hybrid groups are TLS
   1.3 mechanisms. Migrating outbound work traffic needs a
   separate decision: move `WorkSSL` to a TLS 1.3-capable context
   first, then the hybrid applies there too. The remote servers it
   talks to may not support hybrid groups at all.
5. **Measurement.** The tree logs no negotiated TLS parameters
   today. Before rolling out the hybrid, add per-connection
   logging of version, suite and negotiated group (available from
   the `SSL` object after the handshake). Without it, the rollout
   cannot be verified in production — the same gap this pack's
   local harness exists to fill for the pre-migration state.
6. **FIPS / compliance.** If any deployment requires a validated
   cryptographic module, note that the FIPS-validated OpenSSL
   module at the time of writing predates native ML-KEM; a
   FIPS-bound deployment cannot use OpenSSL's native ML-KEM in a
   validated module yet. That gate is external to this tree and
   may delay adoption for regulated operators.

## 6. Sequencing (recommended order)

1. Remove RSA key-transport suites from the overlay cipher list
   (classical hardening; closes the TLS 1.2 HNDL path that needs
   no quantum computer at all — only a key compromise).
2. Upgrade OpenSSL 1.1.1w → 3.5 LTS (Conan pin, CMake floor, EVP
   rewrite of `initAnonymous`, full build + test pass).
3. Set the TLS 1.3 group list explicitly with `X25519MLKEM768`
   first and classical fallback second; add per-connection logging
   of the negotiated group.
4. Roll out, measure the hybrid share from the logs, and only then
   decide whether and when to drop the classical fallback.
5. Separately, design the ML-DSA node-identity migration (open
   question 2) — the transport change does not cover it.
