#!/usr/bin/env python3
"""Local TLS handshake-behavior harness for the postfiatd peer overlay.

Reproduces, on loopback only, the TLS configuration the pinned postfiatd
tree writes in src/libxrpl/basics/make_SSLContext.cpp (get_context /
make_SSLContext / initAnonymous) and records what actually negotiates.

What it does:
  1. Builds, deterministically, an RSA-2048 self-signed certificate
     exactly like initAnonymous does: empty subject/issuer, 128-bit
     serial, SHA-256 signature, validity 2 years, extensions
     basicConstraints critical CA:FALSE, extKeyUsage critical
     serverAuth+clientAuth, keyUsage critical digitalSignature,
     subjectKeyIdentifier (SHA-1 hash of the public key).
     The RSA key is generated from a fixed seed (20261113) with a
     pure-Python Miller-Rabin prime search, so the key, the certificate
     and its SHA-256 fingerprint are identical on every run.
     (Deviations from the code, recorded, not hidden: the code draws
     the serial from BN_rand and the validity window from the wall
     clock at server start; this harness fixes both so the output is
     reproducible. The code's RSA key is drawn from OpenSSL's CSPRNG;
     the harness draws its primes from a seeded PRNG instead. The
     certificate is a throwaway test artifact, never used outside
     loopback.)
  2. Extracts the embedded 2048-bit DH parameters from
     make_SSLContext.cpp, checks them with `openssl dhparam -check`,
     and negotiates a DHE suite against them via `openssl s_server`
     (the Python ssl module exposes no API to set temporary DH
     parameters, so the DHE variant uses the openssl CLI server).
  3. Runs ten handshake variants (loopback, 127.0.0.1, 3 attempts
     each) between a TLS server and a TLS client configured like the
     overlay, and records negotiated version, cipher suite and any
     handshake failure, from both ends.
  4. Expands the cipher-list strings with `openssl ciphers -s` and
     classifies every TLS 1.2 suite (key exchange, PFS, AEAD vs CBC)
     plus the five TLS 1.3 suites, into cipher_matrix.csv.

Python standard library only; the only external programs invoked are
the system `openssl` CLI (cipher expansion, DH check, DHE server /
client). No network access beyond loopback. No live peer, validator
or network endpoint is contacted.

Usage:
    python3 harness.py [--tree /path/to/postfiatd-tree-at-0085a1ff]
                       [--out-dir results]
The tree is used only to read make_SSLContext.cpp and to record the
pinned commit (git rev-parse HEAD); the recorded metadata names the
commit, not the local checkout path.
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

HARNESS_VERSION = "1.0.0"
SEED = 20261113
OVERLAY_CIPHER_LIST = "TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL"
# Fixed stand-ins for the code's wall-clock-derived values (see docstring).
CERT_NOT_BEFORE = "261112000000Z"   # 2026-11-12 00:00:00 UTC
CERT_NOT_AFTER = "281112000000Z"    # 2028-11-12 00:00:00 UTC (2 years)
CERT_SERIAL = 0x20261113000000000000000000000042  # fixed 128-bit serial
ATTEMPTS_PER_VARIANT = 3

# ---------------------------------------------------------------------------
# Deterministic RSA-2048 key generation (seeded PRNG + Miller-Rabin)
# ---------------------------------------------------------------------------

def _miller_rabin(n, bases):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(rng, bits):
    while True:
        cand = (1 << (bits - 1)) | (rng.getrandbits(bits - 2) << 1) | 1
        if _miller_rabin(
                cand, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]):
            return cand


def gen_rsa(rng, bits=2048):
    while True:
        p = _gen_prime(rng, bits // 2)
        q = _gen_prime(rng, bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        if (d * e) % phi == 1:
            return {"p": p, "q": q, "n": n, "e": e, "d": d,
                    "dp": d % (p - 1), "dq": d % (q - 1),
                    "qinv": pow(q, -1, p)}


# ---------------------------------------------------------------------------
# Minimal DER encoder (just enough for PKCS#1 + X.509 as used here)
# ---------------------------------------------------------------------------

def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def _int(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _oid(*arcs):
    out = bytes([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7F]
        a >>= 7
        while a:
            enc.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(enc))
    return _tlv(0x06, out)


def _null():
    return b"\x05\x00"


def _bitstr(data, unused=0):
    return _tlv(0x03, bytes([unused]) + data)


def _oct(data):
    return _tlv(0x04, data)


def _utc(s):
    return _tlv(0x17, s.encode())


def _bool(v):
    return _tlv(0x01, b"\xff" if v else b"\x00")


def _explicit(n, value):
    return _tlv(0xA0 + n, value)


SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")


def _rsa_sign(priv, msg):
    digest = hashlib.sha256(msg).digest()
    t = SHA256_DIGESTINFO_PREFIX + digest
    k = (priv["n"].bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, priv["d"], priv["n"])
    return s.to_bytes(k, "big")


def build_cert(priv):
    """Self-signed certificate mirroring initAnonymous (see docstring)."""
    rsa_pub = _seq(_int(priv["n"]), _int(priv["e"]))
    spki = _seq(_seq(_oid(1, 2, 840, 113549, 1, 1, 1), _null()),
                _bitstr(rsa_pub))
    skid = hashlib.sha1(rsa_pub).digest()  # "hash" per X509V3 "hash" rule
    exts = [
        # basicConstraints critical, CA:FALSE
        _seq(_oid(2, 5, 29, 19), _bool(True), _oct(_seq(_bool(False)))),
        # extKeyUsage critical, serverAuth, clientAuth
        _seq(_oid(2, 5, 29, 37), _bool(True), _oct(_seq(
            _oid(1, 3, 6, 1, 5, 5, 7, 3, 1),
            _oid(1, 3, 6, 1, 5, 5, 7, 3, 2)))),
        # keyUsage critical, digitalSignature
        _seq(_oid(2, 5, 29, 15), _bool(True), _oct(_bitstr(b"\x80", 7))),
        # subjectKeyIdentifier, SHA-1 hash of the public key
        _seq(_oid(2, 5, 29, 14), _oct(_oct(skid))),
    ]
    sigalg = _seq(_oid(1, 2, 840, 113549, 1, 1, 11), _null())
    empty_name = _tlv(0x30, b"")  # the code sets no subject/issuer name
    tbs = _seq(
        _explicit(0, _int(2)),                      # version 3
        _int(CERT_SERIAL),
        sigalg,
        empty_name,                                  # issuer (empty)
        _seq(_utc(CERT_NOT_BEFORE), _utc(CERT_NOT_AFTER)),
        empty_name,                                  # subject (empty)
        spki,
        _explicit(3, _seq(*exts)),
    )
    sig = _rsa_sign(priv, tbs)
    return _seq(tbs, sigalg, _bitstr(sig))


def _pem(kind, der):
    import base64
    body = base64.encodebytes(der).decode()
    return "-----BEGIN %s-----\n%s-----END %s-----\n" % (kind, body, kind)


def _pkcs1_pem(priv):
    der = _seq(_int(0), _int(priv["n"]), _int(priv["e"]), _int(priv["d"]),
               _int(priv["p"]), _int(priv["q"]), _int(priv["dp"]),
               _int(priv["dq"]), _int(priv["qinv"]))
    return _pem("RSA PRIVATE KEY", der)


# ---------------------------------------------------------------------------
# Cipher-list expansion and classification
# ---------------------------------------------------------------------------

def _openssl_ciphers(cipher_string, tls_version):
    out = subprocess.run(
        ["openssl", "ciphers", "-s", "-tls1_%d" % tls_version,
         cipher_string],
        capture_output=True, text=True, check=True)
    text = out.stdout.strip()
    return text.split(":") if text else []


def classify_suite(name, tls_version):
    """Key exchange / PFS / AEAD-vs-CBC classification from the suite name.

    TLS 1.3 suites name only AEAD+hash; key exchange is always
    ephemeral (EC)DHE (RFC 8446) and is negotiated via extensions.
    """
    if tls_version == "1.3":
        return {"key_exchange": "(EC)DHE (ephemeral, per RFC 8446)",
                "authentication": "certificate (any)",
                "encryption": "AEAD",
                "forward_secrecy": "yes"}
    if name.startswith("ECDHE-"):
        kx, auth = "ECDHE", name.split("-")[1]
    elif name.startswith("DHE-"):
        kx, auth = "DHE", name.split("-")[1]
    elif name.startswith(("AES", "ARIA", "CAMELLIA", "SEED", "DES", "RC4",
                          "IDEA")):
        kx, auth = "RSA", "RSA"
    elif name.startswith("PSK"):
        kx, auth = "PSK", "PSK"
    elif name.startswith("SRP"):
        kx, auth = "SRP", "SRP"
    else:
        kx, auth = "other", "other"
    if ("GCM" in name or "CCM" in name or "CHACHA20" in name
            or "POLY1305" in name):
        enc = "AEAD"
    elif "CBC" in name or name.endswith(("-SHA", "-SHA256", "-SHA384")):
        # OpenSSL names TLS 1.2 CBC suites by their MAC hash, e.g.
        # ECDHE-RSA-AES256-SHA384; a bare -SHA* suffix means CBC.
        enc = "CBC"
    elif "RC4" in name:
        enc = "RC4 (stream)"
    elif "NULL" in name:
        enc = "none"
    elif "DES" in name:
        enc = "DES/3DES"
    else:
        enc = "other"
    return {"key_exchange": kx,
            "authentication": auth,
            "encryption": enc,
            "forward_secrecy": "yes" if kx in ("ECDHE", "DHE") else "no"}


def build_cipher_matrix(out_dir):
    overlay = _openssl_ciphers(OVERLAY_CIPHER_LIST, 2)
    default = _openssl_ciphers("DEFAULT", 2)
    all12 = _openssl_ciphers("ALL", 2)
    tls13 = _openssl_ciphers("DEFAULT", 3)
    rows = {}
    for name in all12:
        rows[name] = ("1.2", name in overlay, name in default, True)
    for name in overlay:  # in case the overlay list has a suite ALL lacks
        rows.setdefault(name, ("1.2", True, name in default, name in all12))
    for name in tls13:
        rows[name] = ("1.3", None, None, None)
    records = []
    for name in sorted(rows):
        ver, in_ov, in_def, in_all = rows[name]
        c = classify_suite(name, ver)
        records.append({
            "suite_openssl_name": name,
            "tls_version": ver,
            "key_exchange": c["key_exchange"],
            "authentication": c["authentication"],
            "encryption": c["encryption"],
            "forward_secrecy": c["forward_secrecy"],
            "in_overlay_list": ("n/a (cipher list does not apply to TLS 1.3)"
                                if ver == "1.3" else ("yes" if in_ov else "no")),
            "in_openssl_default_list": ("n/a (TLS 1.3)" if ver == "1.3"
                                        else ("yes" if in_def else "no")),
            "in_all_list": ("n/a (TLS 1.3)" if ver == "1.3"
                            else ("yes" if in_all else "no")),
        })
    path = os.path.join(out_dir, "cipher_matrix.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        w.writerows(records)
    return {
        "overlay_tls12_suite_count": len(overlay),
        "default_tls12_suite_count": len(default),
        "all_tls12_suite_count": len(all12),
        "tls13_suite_count": len(tls13),
        "tls13_suites": tls13,
        "overlay_tls12_suites": overlay,
        "overlay_excludes_vs_all": sorted(set(all12) - set(overlay)),
        "overlay_includes_rsa_kx": [s for s in overlay
                                    if classify_suite(s, "1.2")["key_exchange"] == "RSA"],
        "overlay_includes_cbc": [s for s in overlay
                                 if classify_suite(s, "1.2")["encryption"] == "CBC"],
        "rows": len(records),
    }


# ---------------------------------------------------------------------------
# Handshake variants (Python ssl; DHE variant via openssl s_server/s_client)
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _python_variant(variant, cert_path, key_path):
    """One variant via Python's ssl module; returns a result dict."""
    cfg = variant["config"]
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = cfg["server_min"]
    if cfg.get("server_max"):
        sctx.maximum_version = cfg["server_max"]
    if cfg.get("server_ciphers"):
        sctx.set_ciphers(cfg["server_ciphers"])
    if cfg.get("server_ciphersuites"):
        sctx.set_ciphersuites(cfg["server_ciphersuites"])
    sctx.load_cert_chain(cert_path, key_path)
    sctx.options |= ssl.OP_SINGLE_DH_USE
    results = []
    attempts = []
    for _ in range(ATTEMPTS_PER_VARIANT):
        server_seen = []
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", 0))
        ls.listen(4)
        port = ls.getsockname()[1]

        def serve():
            try:
                conn, _ = ls.accept()
                try:
                    ss = sctx.wrap_socket(conn, server_side=True)
                    server_seen.append({"version": ss.version(),
                                        "cipher": ss.cipher()[0]})
                    ss.close()
                except Exception as exc:  # noqa: BLE001 - recorded verbatim
                    server_seen.append({"error": type(exc).__name__,
                                        "message": str(exc)})
            except Exception as exc:  # noqa: BLE001
                server_seen.append({"error": type(exc).__name__,
                                    "message": str(exc)})
            finally:
                ls.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.minimum_version = cfg["client_min"]
        if cfg.get("client_max"):
            cctx.maximum_version = cfg["client_max"]
        if cfg.get("client_ciphers"):
            cctx.set_ciphers(cfg["client_ciphers"])
        if cfg.get("client_ciphersuites"):
            cctx.set_ciphersuites(cfg["client_ciphersuites"])
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE  # mirrors verify_none in the code
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) \
                    as raw:
                with cctx.wrap_socket(raw,
                                      server_hostname="localhost") as cs:
                    attempts.append({"outcome": "success",
                                     "version": cs.version(),
                                     "cipher": cs.cipher()[0]})
        except Exception as exc:  # noqa: BLE001 - recorded verbatim
            attempts.append({"outcome": "failure",
                             "error": type(exc).__name__,
                             "message": str(exc)})
        t.join(timeout=10)
        results.append({"client": attempts[-1], "server": server_seen[0]
                        if server_seen else None})
    return results


def _openssl_variant(variant, cert_path, key_path, dhparam_path, workdir):
    """DHE variant via openssl s_server / s_client (Python ssl cannot set
    temporary DH parameters, so the embedded DH parameters can only be
    exercised through the CLI server)."""
    cfg = variant["config"]
    port = _free_port()
    import tempfile
    _fd, server_log = tempfile.mkstemp(prefix="s_server-", suffix=".log")
    os.close(_fd)
    with open(server_log, "wb") as log:
        server = subprocess.Popen(
            ["openssl", "s_server", "-accept", str(port),
             "-cert", cert_path, "-key", key_path,
             "-tls1_2", "-cipher", cfg["server_ciphers"],
             "-dhparam", dhparam_path, "-naccept", "1", "-www"],
            stdout=log, stderr=subprocess.STDOUT)
        try:
            import time
            time.sleep(1)
            client = subprocess.run(
                ["openssl", "s_client", "-connect",
                 "127.0.0.1:%d" % port, "-tls1_2",
                 "-cipher", cfg["client_ciphers"]],
                input=b"", capture_output=True, timeout=15)
            text = client.stdout.decode("utf-8", "replace")
            m_proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.M)
            m_ciph = re.search(r"^\s*Cipher\s*:\s*(\S+)", text, re.M)
            ok = bool(m_ciph and m_ciph.group(1) != "0000")
            return [{"client": {"outcome": "success" if ok else "failure",
                                "version": m_proto.group(1) if m_proto else None,
                                "cipher": m_ciph.group(1) if m_ciph else None},
                     "server": {"note": "openssl s_server; see dh_params.txt "
                                        "for the embedded DH parameters"}}]
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


VARIANTS = [
    {"id": "V1", "name": "overlay-as-written",
     "description": "Server and client configured exactly as the code "
                    "writes them: TLS minimum 1.2, no maximum (TLS 1.3 "
                    "allowed), cipher list "
                    "'TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL', RSA-2048 "
                    "self-signed certificate, no certificate verification.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": OVERLAY_CIPHER_LIST}},
    {"id": "V2", "name": "tls13-only",
     "description": "Both ends restricted to TLS 1.3 with the default "
                    "TLS 1.3 ciphersuites (the code never configures "
                    "TLS 1.3 ciphersuites, so this is the default set).",
     "config": {"server_min": ssl.TLSVersion.TLSv1_3,
                "server_max": ssl.TLSVersion.TLSv1_3,
                "client_min": ssl.TLSVersion.TLSv1_3,
                "client_max": ssl.TLSVersion.TLSv1_3}},
    {"id": "V3", "name": "relaxed-tls12",
     "description": "TLS 1.2 only, cipher list relaxed to 'ALL' on both "
                    "ends: shows what the overlay restriction actually "
                    "excludes, by contrast with V4.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_max": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": "ALL",
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_max": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": "ALL"}},
    {"id": "V4", "name": "overlay-tls12-only",
     "description": "Overlay cipher list with TLS 1.2 forced on both "
                    "ends: shows which TLS 1.2 suite the overlay "
                    "configuration negotiates when TLS 1.3 is out of "
                    "the picture.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_max": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_max": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": OVERLAY_CIPHER_LIST}},
    {"id": "V5", "name": "rsa-key-transport-tls12",
     "description": "Overlay server (TLS 1.2, overlay cipher list); "
                    "client offers ONLY the RSA key-transport suite "
                    "AES256-GCM-SHA384 (TLS_RSA_WITH_AES_256_GCM_SHA384). "
                    "Tests whether the overlay cipher list permits "
                    "non-forward-secret RSA key transport.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_max": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_max": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": "AES256-GCM-SHA384"}},
    {"id": "V6", "name": "cbc-blocked-by-overlay",
     "description": "Overlay server (TLS 1.2, overlay cipher list); "
                    "client offers ONLY the CBC suite "
                    "ECDHE-RSA-AES256-SHA384. Expected failure: the "
                    "!CBC exclusion leaves no shared cipher.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_max": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_max": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": "ECDHE-RSA-AES256-SHA384"}},
    {"id": "V7", "name": "cbc-allowed-when-relaxed",
     "description": "Control for V6: same CBC-only client against a "
                    "server with the cipher list relaxed to 'ALL'. "
                    "Expected success with the CBC suite.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_max": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": "ALL",
                "client_min": ssl.TLSVersion.TLSv1_2,
                "client_max": ssl.TLSVersion.TLSv1_2,
                "client_ciphers": "ECDHE-RSA-AES256-SHA384"}},
    {"id": "V8", "name": "tls11-rejected",
     "description": "Overlay server; client restricted to TLS 1.1 "
                    "(security level lowered on the client only, so the "
                    "client can even offer it). Expected failure: the "
                    "server disables TLS 1.0/1.1.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_2,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_1,
                "client_max": ssl.TLSVersion.TLSv1_1,
                "client_ciphers": "ECDHE-RSA-AES256-SHA:@SECLEVEL=0"}},
    {"id": "V9", "name": "tls12-dhe-embedded-params",
     "description": "TLS 1.2, overlay cipher list, client offers ONLY "
                    "DHE-RSA-AES256-GCM-SHA384; server is openssl "
                    "s_server loaded with the embedded 2048-bit DH "
                    "parameters extracted from make_SSLContext.cpp. "
                    "Tests the code's DHE path end to end.",
     "config": {"server_ciphers": OVERLAY_CIPHER_LIST,
                "client_ciphers": "DHE-RSA-AES256-GCM-SHA384"},
     "via_openssl": True},
    {"id": "V10", "name": "tls13-ciphersuites-unrestricted",
     "description": "TLS 1.3 only, server cipher list set to the overlay "
                    "string (which per OpenSSL documentation does not "
                    "affect TLS 1.3 ciphersuites): shows TLS 1.3 still "
                    "negotiates its default suites, including "
                    "ChaCha20-Poly1305, which the '!CBC' wording never "
                    "touches.",
     "config": {"server_min": ssl.TLSVersion.TLSv1_3,
                "server_max": ssl.TLSVersion.TLSv1_3,
                "server_ciphers": OVERLAY_CIPHER_LIST,
                "client_min": ssl.TLSVersion.TLSv1_3,
                "client_max": ssl.TLSVersion.TLSv1_3}},
]


# ---------------------------------------------------------------------------
# DH parameters: extract from the pinned tree and check them
# ---------------------------------------------------------------------------

def extract_dh_params(tree):
    path = os.path.join(tree, "src", "libxrpl", "basics",
                        "make_SSLContext.cpp")
    with open(path) as f:
        src = f.read()
    i = src.index("-----BEGIN DH PARAMETERS-----") + \
        len("-----BEGIN DH PARAMETERS-----")
    j = src.index("-----END DH PARAMETERS-----")
    body = src[i:j].replace("\\n", "").replace('"', "")
    body = re.sub(r"\s+", "", body)
    lines = [body[k:k + 64] for k in range(0, len(body), 64)]
    return ("-----BEGIN DH PARAMETERS-----\n" + "\n".join(lines) +
            "\n-----END DH PARAMETERS-----\n")


# ---------------------------------------------------------------------------
# Certificate properties (via openssl x509 -text, recorded verbatim)
# ---------------------------------------------------------------------------

def cert_properties(cert_path):
    out = subprocess.run(["openssl", "x509", "-in", cert_path, "-text",
                          "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True)
    text = out.stdout
    der = subprocess.run(["openssl", "x509", "-in", cert_path, "-outform",
                          "DER"], capture_output=True, check=True).stdout
    fp = hashlib.sha256(der).hexdigest()

    def grab(pattern):
        m = re.search(pattern, text, re.M)
        return m.group(1).strip() if m else None

    def grab_line(label):
        # Same-line value only: the Subject:/Issuer: lines are empty in
        # this certificate (the code sets no name), so a \s* pattern
        # would silently swallow the following line.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(label):
                return stripped[len(label):].strip()
        return None

    return {
        "sha256_fingerprint": fp,
        "serial": grab(r"Serial Number:\s*\n\s*([0-9a-f:]+)"),
        "signature_algorithm": grab(r"Signature Algorithm:\s*(\S+)"),
        "issuer": grab_line("Issuer:"),
        "subject": grab_line("Subject:"),
        "not_before": grab(r"Not Before:\s*(.*)"),
        "not_after": grab(r"Not After :\s*(.*)"),
        "public_key_algorithm": grab(
            r"Subject Public Key Info:\s*\n\s*Public Key Algorithm:\s*(\S+)"),
        "public_key_bits": grab(r"Public-Key:\s*\((\d+) bit\)"),
        "extensions_present": sorted(set(re.findall(
            r"X509v3 ([A-Za-z ]+):", text))),
        "openssl_x509_text": text,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", default=os.environ.get("POSTFIATD_TREE", ""))
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()
    pack_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out_dir or os.path.join(pack_dir, "results")
    os.makedirs(out_dir, exist_ok=True)

    tree = args.tree
    if not tree or not os.path.isdir(tree):
        raise SystemExit(
            "harness.py: a postfiatd tree at the pinned commit is required "
            "(--tree PATH or POSTFIATD_TREE); it is used to read "
            "make_SSLContext.cpp and to record the pinned commit")
    commit = None
    if tree and os.path.isdir(os.path.join(tree, ".git")):
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=tree, capture_output=True,
            text=True, check=True).stdout.strip()
    elif tree:
        # Detached worktree without .git dir still resolves via git -C.
        commit = subprocess.run(
            ["git", "-C", tree, "rev-parse", "HEAD"], capture_output=True,
            text=True, check=True).stdout.strip()

    openssl_cli = subprocess.run(["openssl", "version"], capture_output=True,
                                 text=True, check=True).stdout.strip()

    # 1. Deterministic test certificate + key.
    rng = random.Random(SEED)
    priv = gen_rsa(rng)
    cert_der = build_cert(priv)
    cert_path = os.path.join(out_dir, "test_cert.pem")
    key_path = os.path.join(out_dir, "test_key.pem")
    with open(cert_path, "w") as f:
        f.write(_pem("CERTIFICATE", cert_der))
    with open(key_path, "w") as f:
        f.write(_pkcs1_pem(priv))
    os.chmod(key_path, 0o600)
    props = cert_properties(cert_path)
    with open(os.path.join(out_dir, "cert_properties.json"), "w") as f:
        json.dump(props, f, indent=2)
        f.write("\n")

    # 2. Embedded DH parameters: extract, check, record.
    dh_pem = extract_dh_params(tree)
    dh_path = os.path.join(out_dir, "dh_params.pem")
    with open(dh_path, "w") as f:
        f.write(dh_pem)
    dh_check = subprocess.run(
        ["openssl", "dhparam", "-in", dh_path, "-text", "-noout", "-check"],
        capture_output=True, text=True)
    dh_text = dh_check.stdout + dh_check.stderr
    with open(os.path.join(out_dir, "dh_params.txt"), "w") as f:
        f.write(dh_text)
    dh_bits = re.search(r"DH Parameters: \((\d+) bit\)", dh_text)
    dh_ok = "DH parameters appear to be ok." in dh_text

    # 3. Cipher matrix.
    matrix = build_cipher_matrix(out_dir)

    # 4. Handshake variants.
    variant_results = []
    for variant in VARIANTS:
        if variant.get("via_openssl"):
            attempts = _openssl_variant(variant, cert_path, key_path,
                                        dh_path, out_dir)
        else:
            attempts = _python_variant(variant, cert_path, key_path)
        outcomes = [a["client"]["outcome"] for a in attempts]
        negotiated = [a["client"].get("cipher") for a in attempts
                      if a["client"]["outcome"] == "success"]
        versions = [a["client"].get("version") for a in attempts
                    if a["client"]["outcome"] == "success"]
        variant_results.append({
            "id": variant["id"],
            "name": variant["name"],
            "description": variant["description"],
            "attempts": attempts,
            "summary": {
                "attempts": len(attempts),
                "successes": outcomes.count("success"),
                "failures": outcomes.count("failure"),
                "negotiated_version": versions[0] if versions else None,
                "negotiated_cipher": negotiated[0] if negotiated else None,
                "all_attempts_agree": len(set(
                    (a["client"]["outcome"],
                     a["client"].get("version"),
                     a["client"].get("cipher")) for a in attempts)) == 1,
            },
        })

    result = {
        "harness": "harness.py",
        "harness_version": HARNESS_VERSION,
        "seed": SEED,
        "pinned_commit": commit,
        "pinned_tree_file": "src/libxrpl/basics/make_SSLContext.cpp",
        "overlay_cipher_list_as_written": OVERLAY_CIPHER_LIST,
        "environment": {
            "python": sys.version.split()[0],
            "python_ssl_openssl_version": ssl.OPENSSL_VERSION,
            "openssl_cli_version": openssl_cli,
            "platform": platform.platform(),
        },
        "certificate": {
            "key_type": "RSA",
            "key_bits": 2048,
            "signature_algorithm": props["signature_algorithm"],
            "serial": props["serial"],
            "not_before": props["not_before"],
            "not_after": props["not_after"],
            "sha256_fingerprint": props["sha256_fingerprint"],
            "subject": props["subject"],
            "issuer": props["issuer"],
        },
        "dh_parameters": {
            "bits": int(dh_bits.group(1)) if dh_bits else None,
            "check_ok": dh_ok,
            "source": "embedded defaultDH in make_SSLContext.cpp",
        },
        "cipher_matrix": {k: v for k, v in matrix.items()
                          if k not in ("overlay_tls12_suites",)},
        "cipher_matrix_csv": "cipher_matrix.csv",
        "variants": variant_results,
        "scope": "Loopback-only local rig. No live peer, validator or "
                 "network endpoint was contacted. The harness measures "
                 "a TLS client/server pair configured like the overlay; "
                 "it is NOT a measurement of live peer connections.",
    }
    with open(os.path.join(out_dir, "handshake_results.json"), "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    lines = [
        "Handshake harness summary (harness.py %s, seed %d)"
        % (HARNESS_VERSION, SEED),
        "Pinned commit: %s" % commit,
        "Local OpenSSL (library): %s" % ssl.OPENSSL_VERSION,
        "Local OpenSSL (CLI): %s" % openssl_cli,
        "Overlay cipher list as written: %s" % OVERLAY_CIPHER_LIST,
        "TLS 1.2 suites in overlay list: %d (local OpenSSL)"
        % matrix["overlay_tls12_suite_count"],
        "TLS 1.2 suites in OpenSSL DEFAULT: %d"
        % matrix["default_tls12_suite_count"],
        "TLS 1.2 suites in ALL: %d" % matrix["all_tls12_suite_count"],
        "TLS 1.3 suites (defaults, never configured by the code): %d"
        % matrix["tls13_suite_count"],
        "RSA key-transport suites still in overlay list: %s"
        % ", ".join(matrix["overlay_includes_rsa_kx"]),
        "CBC suites still in overlay list: %s"
        % (", ".join(matrix["overlay_includes_cbc"]) or "none"),
        "Test certificate: RSA %s-bit, %s, fingerprint %s"
        % (props["public_key_bits"], props["signature_algorithm"],
           props["sha256_fingerprint"]),
        "Embedded DH parameters: %s-bit, check ok: %s"
        % (dh_bits.group(1) if dh_bits else "?", dh_ok),
        "",
    ]
    for v in variant_results:
        s = v["summary"]
        lines.append(
            "%s %s: %d/%d succeeded; version=%s cipher=%s" % (
                v["id"], v["name"], s["successes"], s["attempts"],
                s["negotiated_version"], s["negotiated_cipher"]))
    with open(os.path.join(out_dir, "summary.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
