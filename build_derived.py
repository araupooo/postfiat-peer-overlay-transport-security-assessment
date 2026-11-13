#!/usr/bin/env python3
"""Regenerate derived outputs from the harness results.

Reads results/handshake_results.json and results/cipher_matrix.csv and
writes:
  - results/cipher_matrix.md  (human-readable form of the matrix)
  - docs/index.html            (canonical results page)

Deterministic: no timestamps, no random data, fixed ordering.
"""

import csv
import html
import json
import os
import sys

PACK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(PACK_DIR, "results")


def load_results():
    with open(os.path.join(RESULTS, "handshake_results.json")) as f:
        return json.load(f)


def load_matrix():
    with open(os.path.join(RESULTS, "cipher_matrix.csv"), newline="") as f:
        return list(csv.DictReader(f))


def build_matrix_md(data, rows):
    overlay = [r for r in rows if r["in_overlay_list"] == "yes"]
    rsa_in_overlay = [r for r in overlay
                      if r["key_exchange"] == "RSA"]
    ecdhe_in_overlay = [r for r in overlay
                        if r["key_exchange"] == "ECDHE"]
    dhe_in_overlay = [r for r in overlay if r["key_exchange"] == "DHE"]
    cbc_in_overlay = [r for r in overlay if r["encryption"] == "CBC"]
    excluded = [r for r in rows
                if r["tls_version"] == "1.2"
                and r["in_overlay_list"] == "no"]
    tls13 = [r for r in rows if r["tls_version"] == "1.3"]
    lines = []
    lines.append("# Cipher-negotiation matrix")
    lines.append("")
    lines.append("Expansion of the cipher-list strings under the local "
                 "OpenSSL (%s), recorded in "
                 "`results/handshake_results.json` under `cipher_matrix`."
                 % data["environment"]["openssl_cli_version"])
    lines.append("")
    lines.append("Cipher list as written in the code "
                 "(`src/libxrpl/basics/make_SSLContext.cpp:104`): "
                 "`%s`."
                 % data["overlay_cipher_list_as_written"])
    lines.append("")
    lines.append("## Counts (TLS 1.2, local OpenSSL)")
    lines.append("")
    lines.append("| List | Suites |")
    lines.append("|---|---:|")
    lines.append("| Overlay list as written | %d |"
                 % data["cipher_matrix"]["overlay_tls12_suite_count"])
    lines.append("| OpenSSL DEFAULT | %d |"
                 % data["cipher_matrix"]["default_tls12_suite_count"])
    lines.append("| ALL | %d |"
                 % data["cipher_matrix"]["all_tls12_suite_count"])
    lines.append("| TLS 1.3 defaults (never configured by the code) | %d |"
                 % data["cipher_matrix"]["tls13_suite_count"])
    lines.append("")
    lines.append("## What the overlay list contains (TLS 1.2, %d suites)"
                 % len(overlay))
    lines.append("")
    lines.append("- ECDHE suites: %d" % len(ecdhe_in_overlay))
    lines.append("- DHE suites: %d" % len(dhe_in_overlay))
    lines.append("- RSA key-transport suites (no forward secrecy): %d — %s"
                 % (len(rsa_in_overlay),
                    ", ".join(r["suite_openssl_name"]
                              for r in rsa_in_overlay)))
    lines.append("- CBC suites: %d" % len(cbc_in_overlay))
    lines.append("")
    lines.append("The `!CBC` exclusion removes all %d CBC suites that "
                 "`ALL` offers; the `!DSS`, `!PSK`, `!eNULL` and `!aNULL` "
                 "exclusions remove the DSS, PSK, null-encryption and "
                 "anonymous suites. What the string does **not** exclude "
                 "is RSA key transport: %d RSA suites remain, and variant "
                 "V5 of the harness negotiates one of them "
                 "(TLS_RSA_WITH_AES_256_GCM_SHA384)."
                 % (len([r for r in excluded
                         if r["encryption"] == "CBC"]),
                    len(rsa_in_overlay)))
    lines.append("")
    lines.append("## TLS 1.3 suites (%d, defaults)" % len(tls13))
    lines.append("")
    lines.append("The code never calls `SSL_CTX_set_ciphersuites`, so the "
                 "TLS 1.3 suite list is whatever the linked OpenSSL "
                 "offers by default. `SSL_CTX_set_cipher_list` does not "
                 "affect TLS 1.3 ciphersuites (OpenSSL documentation, "
                 "`SSL_CTX_set_cipher_list(3)`), so the `!CBC` wording "
                 "has no effect on TLS 1.3 at all — and TLS 1.3 has no "
                 "CBC suites to exclude in the first place (RFC 8446).")
    lines.append("")
    for r in tls13:
        lines.append("- `%s`" % r["suite_openssl_name"])
    lines.append("")
    lines.append("## Full matrix")
    lines.append("")
    lines.append("Same data as `cipher_matrix.csv`. `in_overlay_list` "
                 "is `n/a` for TLS 1.3 rows: the cipher list does not "
                 "apply to TLS 1.3 suites.")
    lines.append("")
    lines.append("| Suite | TLS | Key exchange | Auth | Encryption | "
                 "Forward secrecy | In overlay list |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in rows:
        lines.append("| `%s` | %s | %s | %s | %s | %s | %s |" % (
            r["suite_openssl_name"], r["tls_version"], r["key_exchange"],
            r["authentication"], r["encryption"], r["forward_secrecy"],
            r["in_overlay_list"]))
    lines.append("")
    lines.append("Notes")
    lines.append("")
    lines.append("- ECDSA-authenticated suites (`ECDHE-ECDSA-*`) are "
                 "listed by the cipher string but cannot negotiate "
                 "against the overlay's RSA certificate: the server has "
                 "no ECDSA key. They are in the list, not on the wire.")
    lines.append("- Suite counts depend on the linked OpenSSL version: "
                 "the pinned library is 1.1.1w, the harness ran against "
                 "local OpenSSL 3.0.13. The *shape* of the finding "
                 "(RSA key transport still permitted, CBC excluded, "
                 "TLS 1.3 untouched) follows from the cipher string and "
                 "the OpenSSL API, not from the version.")
    lines.append("")
    return "\n".join(lines)


def build_index_html(data, rows):
    variants = data["variants"]
    env = data["environment"]
    cert = data["certificate"]
    dh = data["dh_parameters"]
    cm = data["cipher_matrix"]

    def vrow(v):
        s = v["summary"]
        outcome = ("succeeded %d/%d" % (s["successes"], s["attempts"])
                   if s["successes"] else "failed %d/%d"
                   % (s["attempts"], s["attempts"]))
        return ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td></tr>" % (
                    html.escape(v["id"]), html.escape(v["name"]),
                    html.escape(outcome),
                    html.escape(str(s["negotiated_version"])),
                    html.escape(str(s["negotiated_cipher"])),
                    html.escape(v["description"])))

    vrows = "\n".join(vrow(v) for v in variants)
    rsa_list = ", ".join("`%s`" % s for s in cm["overlay_includes_rsa_kx"])
    tls13_list = ", ".join("`%s`" % s for s in cm["tls13_suites"])
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Post-Quantum Peer-Overlay Transport Security Assessment</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;
padding:0 1em;line-height:1.55;color:#1a1a1a}
h1{font-size:1.5em}h2{font-size:1.2em;margin-top:1.6em}
table{border-collapse:collapse;width:100%%;font-size:.92em}
th,td{border:1px solid #bbb;padding:.35em .5em;text-align:left;
vertical-align:top}
th{background:#eee}code{background:#f2f2f2;padding:0 .2em}
.warn{background:#fff4d6;border-left:4px solid #c90;padding:.6em 1em}
.lim{background:#f2f2f2;border-left:4px solid #888;padding:.6em 1em}
</style>
</head>
<body>
<h1>Post-Quantum Peer-Overlay Transport Security Assessment</h1>
<p>Transport-security assessment of the postfiatd peer overlay under a
post-quantum threat model. Pinned tree: postfiatd main commit
<code>%(commit)s</code>. Harness <code>harness.py</code> version
<code>%(hver)s</code>, seed <code>%(seed)s</code>.</p>

<h2>Headline findings</h2>
<ul>
<li><b>Peer TLS is TLS 1.2 / 1.3 with a 2048-bit RSA self-signed
certificate, and no certificate verification.</b> The overlay context
is built by <code>make_SSLContext("")</code>; verification is
<code>verify_none</code> on both ends of a peer connection. Peer
authentication does not come from TLS at all: it comes from the
overlay handshake above TLS, where each peer signs a value derived
from the TLS Finished messages with its long-term secp256k1 node key.</li>
<li><b>The cipher list as written is
<code>%(cipherlist)s</code>.</b> Under the local OpenSSL it expands to
%(ovcount)s TLS 1.2 suites. It excludes every CBC suite, but it
<b>still permits RSA key transport</b>: %(rsacount)s RSA suites remain
(%(rsalist)s), and harness variant V5 negotiates
<code>TLS_RSA_WITH_AES_256_GCM_SHA384</code> against the overlay
configuration. RSA key transport has no forward secrecy.</li>
<li><b>TLS 1.3 is allowed and is what negotiates by default.</b>
Variant V1 (overlay configuration as written) negotiates TLS 1.3 with
<code>TLS_AES_256_GCM_SHA384</code>. The cipher list does not touch
TLS 1.3 suites at all: the code never calls
<code>SSL_CTX_set_ciphersuites</code>, so all default TLS 1.3 suites
are available (%(tls13)s).</li>
<li><b>Harvest-now-decrypt-later exposure is concentrated in TLS 1.2
sessions.</b> TLS 1.3 sessions use ephemeral (EC)DHE only and are
forward-secret against a later quantum adversary. TLS 1.2 sessions
negotiated with an RSA key-transport suite are decryptable by anyone
who later obtains the (ephemeral, per-process-start) RSA private key
together with the recorded session. Ledger data itself is public;
session keys and the peer handshake are what a recorded session
protects.</li>
<li><b>Hybrid ML-KEM migration is blocked on the pinned OpenSSL,
not on the protocol.</b> OpenSSL 1.1.1w has no ML-KEM support; native
ML-KEM arrived in OpenSSL 3.5 (8 April 2025). The first migration step
is therefore the OpenSSL upgrade, then enabling the
<code>X25519MLKEM768</code> hybrid group (RFC 10024). The overlay's
above-TLS peer authentication (secp256k1 node keys) is a separate,
harder migration and is out of scope for the transport change.</li>
</ul>

<h2>Handshake results (loopback rig, local OpenSSL %(ossl)s)</h2>
<table>
<tr><th>ID</th><th>Variant</th><th>Outcome</th><th>Version</th>
<th>Cipher</th><th>What it tests</th></tr>
%(vrows)s
</table>
<p>Variant details, per-attempt client/server records and the full
cipher matrix are in <code>results/handshake_results.json</code>,
<code>results/cipher_matrix.csv</code> and
<code>results/cipher_matrix.md</code>.</p>

<h2>Test certificate (as generated by the harness)</h2>
<ul>
<li>Key: RSA %(keybits)s-bit, exponent 65537 (seeded, deterministic)</li>
<li>Signature algorithm: %(sigalg)s</li>
<li>Serial: <code>%(serial)s</code></li>
<li>Validity: %(notbefore)s to %(notafter)s</li>
<li>Subject / Issuer: empty (the code sets no name)</li>
<li>SHA-256 fingerprint:
<code>%(fingerprint)s</code></li>
<li>Embedded DH parameters: %(dhbits)s-bit, check passed: %(dhok)s</li>
</ul>

<h2>Exposure summary (per traffic class)</h2>
<table>
<tr><th>Traffic class</th><th>What a passive recorder gets</th>
<th>Decryptable later by a quantum adversary?</th><th>Severity</th></tr>
<tr><td>Peer-overlay validation traffic</td>
<td>Encrypted TLS records; validation messages and ledger data
inside</td><td>Only for TLS 1.2 sessions negotiated with an RSA
key-transport suite, and only if the ephemeral RSA private key is
also obtained while the process runs. TLS 1.3 and (EC)DHE TLS 1.2
sessions stay safe.</td><td>Medium</td></tr>
<tr><td>RPC traffic (secure ports)</td>
<td>Encrypted TLS records; RPC requests/responses inside</td>
<td>Same TLS 1.2 RSA key-transport condition as the overlay; RPC
ports share the same context builder and cipher list, and accept
operator-supplied certificates. Secrets sent over RPC (seeds, keys)
are the highest-value plaintext at risk.</td><td>Medium</td></tr>
<tr><td>Outbound work traffic (WorkSSL)</td>
<td>Encrypted TLS 1.2 records to external hosts</td>
<td>TLS 1.2 client pinned to <code>tlsv12_client</code>; no TLS 1.3,
so no mandatory forward secrecy. RSA key-transport suites are
possible if the remote server selects them; certificate verification
depends on the operator's SSL_VERIFY configuration.</td>
<td>Medium</td></tr>
</table>
<p>Full rationale, per class, is in
<code>exposure_analysis.md</code>.</p>

<div class="warn"><b>What the cipher list does not fix.</b> The
overlay's forward secrecy depends on which TLS version and suite the
two peers actually negotiate, not on the cipher string alone. Under
TLS 1.2 the string still admits RSA key transport; under TLS 1.3 the
string is inert. The honest statement is: forward secrecy is
guaranteed only for TLS 1.3 sessions and for TLS 1.2 sessions that
happen to negotiate (EC)DHE.</div>

<div class="lim"><b>Limits — read before citing.</b> The harness
measures a local TLS rig configured like the overlay; it is not a
measurement of live peer connections — no live peer, validator or
network endpoint was contacted. The ledger was not compiled or run.
Results depend on the local OpenSSL (library %(ossl)s); the pinned
library is 1.1.1w. Negotiated cipher suites at runtime depend on the
peer's offered list, which is not observable statically. See
<code>assumptions.md</code> and <code>claim_evidence_index.md</code>
for the full list.</div>

<h2>Reproduce</h2>
<pre>bash run_all.sh   # re-runs the harness, rebuilds this page, verifies digests
bash verify_digests.sh --check</pre>
<p>See <code>README.md</code> and <code>REPRODUCTION.md</code>.</p>
</body>
</html>
""" % {
        "commit": html.escape(str(data["pinned_commit"])),
        "hver": html.escape(data["harness_version"]),
        "seed": data["seed"],
        "cipherlist": html.escape(data["overlay_cipher_list_as_written"]),
        "ovcount": cm["overlay_tls12_suite_count"],
        "rsacount": len(cm["overlay_includes_rsa_kx"]),
        "rsalist": html.escape(rsa_list),
        "tls13": html.escape(tls13_list),
        "ossl": html.escape(env["python_ssl_openssl_version"]),
        "vrows": vrows,
        "keybits": cert["key_bits"],
        "sigalg": html.escape(str(cert["signature_algorithm"])),
        "serial": html.escape(str(cert["serial"])),
        "notbefore": html.escape(str(cert["not_before"])),
        "notafter": html.escape(str(cert["not_after"])),
        "fingerprint": html.escape(str(cert["sha256_fingerprint"])),
        "dhbits": dh["bits"],
        "dhok": dh["check_ok"],
    }


def main():
    data = load_results()
    rows = load_matrix()
    with open(os.path.join(RESULTS, "cipher_matrix.md"), "w") as f:
        f.write(build_matrix_md(data, rows))
    docs_dir = os.path.join(PACK_DIR, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    with open(os.path.join(docs_dir, "index.html"), "w") as f:
        f.write(build_index_html(data, rows))
    print("build_derived.py: wrote results/cipher_matrix.md, docs/index.html")


if __name__ == "__main__":
    main()
