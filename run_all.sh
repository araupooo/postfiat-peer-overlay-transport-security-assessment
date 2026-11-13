#!/bin/sh
# Regenerate every derived output of this pack from scratch.
#   1. harness.py        -> results/handshake_results.json,
#                           results/cipher_matrix.csv,
#                           results/cert_properties.json,
#                           results/dh_params.txt, results/dh_params.pem,
#                           results/test_cert.pem, results/test_key.pem,
#                           results/summary.txt
#   2. build_derived.py  -> results/cipher_matrix.md, docs/index.html
#   3. verify_digests.sh -> SHA256SUMS (over every other pack file)
#
# The tree is required: set POSTFIATD_TREE=/path/to/postfiatd-tree-at-0085a1ff.
# No network access is used at any step; all handshakes run on loopback.
set -eu
PACK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TREE=${POSTFIATD_TREE:-}
if [ -z "$TREE" ]; then
    echo "run_all.sh: POSTFIATD_TREE is not set (path to a postfiatd tree at commit 0085a1ff)" >&2
    exit 1
fi

cd "$PACK_DIR"
python3 harness.py --tree "$TREE" --out-dir "$PACK_DIR/results"
python3 build_derived.py
./verify_digests.sh
echo "run_all.sh: OK"
