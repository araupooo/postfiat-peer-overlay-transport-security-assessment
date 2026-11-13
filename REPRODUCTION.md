# Fresh-environment reproduction

## Procedure

The pack was copied to a clean temporary directory and rebuilt from
scratch there. Exact commands (run 2026-11-13):

```sh
rm -rf /tmp/repro-tls-pack && mkdir -p /tmp/repro-tls-pack
cp -a <pack>/. /tmp/repro-tls-pack/
cd /tmp/repro-tls-pack
POSTFIATD_TREE=<postfiatd tree at commit 0085a1ff> bash run_all.sh
```

(`<pack>` is the directory holding this file; `<postfiatd tree at
commit 0085a1ff>` is a checkout of the pinned commit. No local
paths are baked into the pack itself; the tree path is supplied
only through the environment.)

## Result

- `bash run_all.sh` in the fresh copy: **exit 0**.
- Comparison of the regenerated outputs against the shipped files:

```sh
diff -r <pack>/results /tmp/repro-tls-pack/results       # IDENTICAL
diff <pack>/docs/index.html /tmp/repro-tls-pack/docs/index.html  # IDENTICAL
diff <pack>/SHA256SUMS /tmp/repro-tls-pack/SHA256SUMS    # IDENTICAL
```

- `./verify_digests.sh --check` in the fresh copy: **exit 0**
  (20 files, 0 failures).

## Environment

- Python 3.12.3, OpenSSL 3.0.13 (library and CLI), git 2.43.0,
  GNU coreutils `sha256sum` (Ubuntu), same machine as the
  authoring run. The harness output is deterministic by design
  (fixed seed 20261113, fixed certificate serial and validity
  window); re-running on a different OpenSSL version may change
  the cipher-suite counts, which is why the local OpenSSL version
  is recorded in `results/handshake_results.json`.
