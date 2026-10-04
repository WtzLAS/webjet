#!/bin/sh
# Test the TPM key storage backend against a software TPM (swtpm):
# unit test, then a full `webjetctl init` + start that seals the identity key,
# and a check that a different TPM can't unseal it.
set -eu
docker run --rm -v "$(cd "$(dirname "$0")/.." && pwd)":/src -w /src \
  -v webjet-cargo-registry:/usr/local/cargo/registry -v webjet-target-tpm:/src/target \
  rust:1-bookworm sh -c '
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq swtpm swtpm-tools tpm2-tools cmake golang clang libclang-dev >/dev/null 2>&1
start_tpm() { mkdir -p $1; swtpm socket --tpmstate dir=$1 --tpm2 --server type=tcp,port=$2 --ctrl type=tcp,port=$(($2+1)) --flags not-need-init,startup-clear --daemon; }
start_tpm /tmp/tpmA 2321
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
tpm2_getcap properties-fixed | head -3
echo "== unit test"
WEBJET_TEST_TPM=1 cargo test -q -p webjetd --lib keystore 2>&1 | tail -25
WEBJET_TEST_TPM=1 cargo test -q -p webjetd --lib keystore >/dev/null 2>&1 || { echo "FAIL: unit test"; exit 1; }
cargo build -q -p webjetd -p webjet-tools 2>/dev/null
B=target/debug
D=/tmp/wj; rm -rf $D; mkdir -p $D
export WEBJET_ROOT_PASSPHRASE=r WEBJET_ACCOUNT_PASSPHRASE=a WEBJET_KEYS=$D/keys
$B/webjetctl root --dir $D/root init >/dev/null
$B/webjetctl account keygen --name alice --pub-out $D/alice.pub >/dev/null
$B/webjetctl root --dir $D/root admin sign --name alice --key $D/alice.pub --out $D/alice.account >/dev/null
$B/webjetctl root --dir $D/root genesis --overlay-pool 10.7.0.0/16 --admin $D/alice.account --out $D/genesis.wj >/dev/null
printf "data_dir = \"$D/node\"\ncontrol_socket = \"$D/node/control.sock\"\n[tun]\nenabled = false\n" > $D/webjetd.toml
echo "== init seals the key in the TPM"
$B/webjetctl init --config $D/webjetd.toml --genesis $D/genesis.wj 2>&1 | tee $D/init.log
head -c 5 $D/node/identity.key | od -c | head -1
grep -q "identity key stored with tpm storage" $D/init.log || { echo "FAIL: key not TPM-sealed"; exit 1; }
echo "== repeated seal/unseal does not exhaust TPM object slots"
for i in 1 2 3 4 5 6; do WEBJET_TEST_TPM=1 cargo test -q -p webjetd --lib keystore::tests::tpm_roundtrip >/dev/null 2>&1 || { echo "FAIL: run $i"; exit 1; }; done; echo ok
echo "== the agent starts with it"
(timeout 5 $B/webjetd -c $D/webjetd.toml run 2>&1 || true) > $D/run.log
head -20 $D/run.log
grep -q "identity key loaded from tpm" $D/run.log || { echo "FAIL: agent could not unseal its key"; exit 1; }
echo "== another TPM cannot unseal it"
start_tpm /tmp/tpmB 2331
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2331
if (timeout 5 $B/webjetd -c $D/webjetd.toml run 2>&1 || true) | grep -q "re-key this node"; then echo "refused as expected"; else echo "FAIL"; exit 1; fi
echo TPM TEST PASSED
'
