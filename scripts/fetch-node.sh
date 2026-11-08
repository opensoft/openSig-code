#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Fetch the pinned Node.js runtime into the gitignored tools/ directory.
#
#   sh scripts/fetch-node.sh
#   PATH="$PWD/tools/node/bin:$PATH"; export PATH
#
# Fail-closed provenance (plan.md "Technical Context", amendments A-001, A-006):
#   1. The clearsigned SHASUMS256.txt.asc is verified with gpg in an ephemeral,
#      short-path GNUPGHOME holding only the release key embedded below. The
#      imported primary fingerprint must equal NODE_SIGNER_FPR, and gpg must
#      report exactly one good, valid signature made by that key.
#   2. The tarball SHA-256 must equal BOTH the line in the signed checksum list
#      (taken from gpg's verified output, never from unsigned text) AND the
#      embedded constant NODE_TARBALL_SHA256.
#   3. The extracted bin/node must equal NODE_BIN_SHA256 and the bundled npm
#      tree must hash to NPM_TREE_SHA256. Only then is it installed at
#      tools/node-v24.22.2-linux-x64/, tools/node pointed at it, and
#      tools/node.receipt.json written.
#
# A missing tool, or any mismatch, exits non-zero before extraction. The host
# Node.js is never used. Every run re-checks an existing install (receipt,
# bin/node against the embedded digest, the npm tree hash, --version) and then
# downloads nothing; a failed re-check discards the install and refetches.
#
# Optional: OPENSIG_NODE_CACHE may name a directory holding
# node-v24.22.2-linux-x64.tar.xz and/or SHASUMS256.txt.asc. Files found there
# are copied instead of downloaded; every verification step still runs on the
# copied bytes.

set -eu

NODE_VERSION=24.22.2
NODE_DIST="node-v${NODE_VERSION}-linux-x64"
NODE_TARBALL="${NODE_DIST}.tar.xz"
NODE_BASE_URL="https://nodejs.org/dist/v${NODE_VERSION}"
NODE_TARBALL_SHA256=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75

# Digests of the verified tarball's contents, measured twice independently on
# 2026-11-08 (installed tree and a fresh extraction): bin/node, and the npm tree
# as computed by npm_tree_sha256 below.
NODE_BIN_SHA256=904a6d3484241d466989f9df9ba3aab822b1496191bdb28230eb491a55c32a52
NPM_TREE_SHA256=dfae950584645ad1cedbe3fec88663a5378673cebc99ab09bc2a1c58a44914f9

# Primary key fingerprint of the releaser who signed v24.22.2 (Antoine du Hamel),
# as listed under "Release keys" in the Node.js v24.22.2 README. Exactly one
# signer is pinned (accepted deviation F4, plan.md A-006); a runtime bump must
# update this pin with its measured signer. The signing key is the ed25519
# primary; the cv25519 subkey 0A178CD0FE03CB4F8780980A039F94E89826F891 is
# encryption-only.
NODE_SIGNER_FPR=5BE8A3F6C8A5C01D106C0AD820B1A390B168D356

# Public key material for NODE_SIGNER_FPR (byte-identical to
# https://github.com/nodejs/release-keys/blob/main/keys/5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc).
NODE_SIGNER_KEY='-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaGA63BYJKwYBBAHaRw8BAQdAo/yU+MutacFmmn0CEX495goNrBxR24235XLM
cvHYjfq0L0FudG9pbmUgZHUgSGFtZWwgPGR1aGFtZWxhbnRvaW5lMTk5NUBnbWFp
bC5jb20+iI4EExYKADYWIQRb6KP2yKXAHRBsCtggsaOQsWjTVgUCaGA63AIbAwQL
CQgHBBUKCQgFFgIDAQACHgUCF4AACgkQILGjkLFo01afgwEA/sLHqsj7ml2vyDoT
KDPE8n9a80ZOh14OfnlOe0cCZA8BAMEOOk7QFI69DIlV1nMiqcFCqQFoSzBU2LkI
R17p/j4NtDNBbnRvaW5lIGR1IEhhbWVsIDxhbnRvaW5lLmR1aGFtZWxAcGxhdGZv
cm1hdGljLmRldj6IjgQTFgoANhYhBFvoo/bIpcAdEGwK2CCxo5CxaNNWBQJpsCMx
AhsDBAsJCAcEFQoJCAUWAgMBAAIeAQIXgAAKCRAgsaOQsWjTVr/sAPwIBsG8g6ND
zoNRTX1wPKBvfZg1NP7tYCyM5sxQfrpuLAEA05AhG4xBILfhL/f0pqR5jXfxg6gz
T6WfeVeS6zeHZwe4OARoYDrcEgorBgEEAZdVAQUBAQdAQVmtih8AO3ryBQMR/22x
WHVKLjAbCiH2cMxNH+iy1RQDAQgHiHgEGBYKACAWIQRb6KP2yKXAHRBsCtggsaOQ
sWjTVgUCaGA63AIbDAAKCRAgsaOQsWjTVu8oAP9Bc+QY+9FikX3YvMgWAqiDlVOy
o0y6UIZGBMSQlF80wAD/d34LqtVIVe9oe5NO3xA75+6Ew8tGeAjUq/ovagr5dAU=
=JsVv
-----END PGP PUBLIC KEY BLOCK-----'

say() { printf 'fetch-node: %s\n' "$*"; }
die() { printf 'fetch-node: ERROR: %s\n' "$*" >&2; exit 1; }

# --- Preconditions -----------------------------------------------------------

# Every external command this script runs (F3). gpgconf is optional: it only
# stops a gpg-agent during cleanup, and --no-autostart keeps one from starting.
for tool in curl gpg sha256sum tar xz mktemp readlink awk sed grep cut find sort uname dirname date chmod mkdir rmdir mv ln rm cp cat; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool (no fallback; install it and rerun)"
done

[ "$(uname -s)" = Linux ] || die "unsupported OS $(uname -s); the pinned runtime is linux-x64 only"
[ "$(uname -m)" = x86_64 ] || die "unsupported CPU $(uname -m); the pinned runtime is linux-x64 only"

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P) || die "cannot resolve repository root"
tools="$root/tools"
dest="$tools/$NODE_DIST"
link="$tools/node"
receipt="$tools/node.receipt.json"

sha256_of() { sha256sum -- "$1" | cut -d ' ' -f 1; }

# Hash of the bundled npm: every regular file under lib/node_modules/npm by
# content, plus every symlink under bin/ and lib/node_modules/npm by target.
npm_tree_sha256() {
  (
    cd -- "$1" || exit 1
    {
      find lib/node_modules/npm -type f -exec sha256sum -- {} +
      find bin lib/node_modules/npm -type l -exec sh -c 'for l do printf "link %s %s\n" "$(readlink -- "$l")" "$l"; done' sh {} +
    } | LC_ALL=C sort | sha256sum | cut -d ' ' -f 1
  )
}

# --- Re-check of an existing install (every run) ----------------------------

receipt_field() { # name -> value of a "name": "value" line in the receipt
  sed -n "s/^  \"$1\": \"\([^\"]*\)\",\{0,1\}\$/\1/p" "$receipt"
}

installed_ok() {
  [ -f "$receipt" ] || return 1
  [ -L "$link" ] || return 1
  [ "$(readlink -- "$link")" = "$NODE_DIST" ] || return 1
  [ -f "$dest/bin/node" ] && [ -x "$dest/bin/node" ] || return 1
  [ "$(receipt_field version)" = "$NODE_VERSION" ] || return 1
  [ "$(receipt_field tarball_sha256)" = "$NODE_TARBALL_SHA256" ] || return 1
  [ "$(receipt_field signer_fingerprint)" = "$NODE_SIGNER_FPR" ] || return 1
  [ "$(receipt_field node_sha256)" = "$NODE_BIN_SHA256" ] || return 1
  [ "$(receipt_field npm_tree_sha256)" = "$NPM_TREE_SHA256" ] || return 1
  # Digests first, then execute: the binary only runs once it matches the pin.
  [ "$(sha256_of "$dest/bin/node")" = "$NODE_BIN_SHA256" ] || return 1
  [ "$(npm_tree_sha256 "$dest")" = "$NPM_TREE_SHA256" ] || return 1
  [ "$("$link/bin/node" --version 2>/dev/null)" = "v$NODE_VERSION" ] || return 1
}

if installed_ok; then
  say "node v$NODE_VERSION already present and re-checked (bin/node and npm tree digests, receipt, --version); nothing downloaded"
  exit 0
fi

if [ -e "$receipt" ] || [ -e "$link" ] || [ -L "$link" ] || [ -e "$dest" ]; then
  say "existing tools/ runtime failed its re-check; discarding it and refetching"
fi

# --- Fetch -------------------------------------------------------------------

mkdir -p -- "$tools"
work=''
gh=''
cleanup() {
  if [ -n "$gh" ]; then
    gpgconf --homedir "$gh" --kill all >/dev/null 2>&1 || true
    rm -rf -- "$gh"
  fi
  if [ -n "$work" ]; then rm -rf -- "$work"; fi
}
work=$(mktemp -d "$tools/.fetch.XXXXXX") || die "cannot create work directory"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# gpg places its sockets in GNUPGHOME when /run/user/<uid> is absent, and a
# socket path is limited to about 107 bytes. The home therefore lives in a short
# base directory, never under an arbitrarily long TMPDIR.
make_gnupghome() {
  for base in /tmp /var/tmp "${TMPDIR:-}"; do
    [ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
    candidate=$(mktemp -d "$base/osg.XXXXXX" 2>/dev/null) || continue
    if [ "${#candidate}" -le 72 ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    rmdir -- "$candidate" 2>/dev/null || true
  done
  return 1
}
gh=$(make_gnupghome) || die "cannot create a GNUPGHOME of at most 72 characters under /tmp, /var/tmp or TMPDIR"
chmod 700 "$gh"

fetch() { # file-name -> $work/file-name
  if [ -n "${OPENSIG_NODE_CACHE:-}" ] && [ -f "$OPENSIG_NODE_CACHE/$1" ]; then
    say "copying $1 from OPENSIG_NODE_CACHE (verified below like a download)"
    cp -- "$OPENSIG_NODE_CACHE/$1" "$work/$1" || die "cannot copy $1 from OPENSIG_NODE_CACHE"
  else
    say "downloading $NODE_BASE_URL/$1"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --retry 3 --connect-timeout 30 --max-time 1800 \
      --output "$work/$1" "$NODE_BASE_URL/$1" || die "download failed: $NODE_BASE_URL/$1"
  fi
}

fetch SHASUMS256.txt.asc
fetch "$NODE_TARBALL"

# --- 1. Signature over the checksum list ------------------------------------

gpg_() { gpg --homedir "$gh" --no-options --batch --no-tty --no-autostart "$@"; }

printf '%s\n' "$NODE_SIGNER_KEY" >"$work/signer.asc"
if ! gpg_ --quiet --import "$work/signer.asc" >"$work/gpg-import.log" 2>&1; then
  cat "$work/gpg-import.log" >&2
  die "release key import failed (gpg output above; GNUPGHOME=$gh)"
fi

imported=$(gpg_ --with-colons --fingerprint 2>/dev/null \
  | awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')
[ "$imported" = "$NODE_SIGNER_FPR" ] \
  || die "imported key fingerprint '$imported' does not equal pinned $NODE_SIGNER_FPR"

# --decrypt on clearsigned input verifies the signature and writes exactly the
# signed text, so unsigned lines around the signed block can never be used.
if ! gpg_ --status-file "$work/gpg.status" --output "$work/SHASUMS256.txt" \
  --decrypt "$work/SHASUMS256.txt.asc" >"$work/gpg-verify.log" 2>&1; then
  cat "$work/gpg-verify.log" >&2
  die "gpg could not verify SHASUMS256.txt.asc (gpg output above)"
fi

if grep -Eq '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY|FAILURE) ' "$work/gpg.status"; then
  cat "$work/gpg.status" >&2
  die "gpg reported a bad, expired, revoked or unverifiable signature"
fi
[ "$(grep -c '^\[GNUPG:\] NEWSIG' "$work/gpg.status")" -eq 1 ] \
  || die "expected exactly one signature on SHASUMS256.txt.asc"
[ "$(grep -c '^\[GNUPG:\] GOODSIG ' "$work/gpg.status")" -eq 1 ] \
  || die "gpg did not report exactly one good signature"
signer=$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $12 }' "$work/gpg.status")
[ "$signer" = "$NODE_SIGNER_FPR" ] \
  || die "valid signature primary key '$signer' does not equal pinned $NODE_SIGNER_FPR"
say "good signature on SHASUMS256.txt.asc from $signer"

# --- 2. Tarball digest: signed line AND embedded constant -------------------

signed_lines=$(awk -v f="$NODE_TARBALL" '$2 == f { n++ } END { print n + 0 }' "$work/SHASUMS256.txt")
[ "$signed_lines" -eq 1 ] || die "signed checksum list has $signed_lines lines for $NODE_TARBALL (expected 1)"
signed_sha=$(awk -v f="$NODE_TARBALL" '$2 == f { print $1 }' "$work/SHASUMS256.txt")
[ "$signed_sha" = "$NODE_TARBALL_SHA256" ] \
  || die "signed checksum $signed_sha does not equal embedded $NODE_TARBALL_SHA256"
actual_sha=$(sha256_of "$work/$NODE_TARBALL")
[ "$actual_sha" = "$signed_sha" ] \
  || die "tarball SHA-256 $actual_sha does not equal the signed checksum $signed_sha"
[ "$actual_sha" = "$NODE_TARBALL_SHA256" ] \
  || die "tarball SHA-256 $actual_sha does not equal embedded $NODE_TARBALL_SHA256"
say "tarball SHA-256 $actual_sha matches the signed list and the embedded constant"

# --- 3. Extract, check contents, install, receipt ---------------------------

mkdir -- "$work/x"
tar -xJf "$work/$NODE_TARBALL" -C "$work/x" --no-same-owner || die "extraction failed"
extracted="$work/x/$NODE_DIST"
[ -f "$extracted/bin/node" ] && [ -x "$extracted/bin/node" ] || die "extracted tree lacks $NODE_DIST/bin/node"
node_sha=$(sha256_of "$extracted/bin/node")
[ "$node_sha" = "$NODE_BIN_SHA256" ] || die "extracted bin/node SHA-256 $node_sha does not equal embedded $NODE_BIN_SHA256"
npm_sha=$(npm_tree_sha256 "$extracted")
[ "$npm_sha" = "$NPM_TREE_SHA256" ] || die "extracted npm tree hash $npm_sha does not equal embedded $NPM_TREE_SHA256"
got=$("$extracted/bin/node" --version) || die "extracted node does not run"
[ "$got" = "v$NODE_VERSION" ] || die "extracted node reports $got, expected v$NODE_VERSION"

rm -f -- "$receipt"
if [ -L "$link" ] || [ -f "$link" ]; then rm -f -- "$link"; elif [ -e "$link" ]; then rm -rf -- "$link"; fi
rm -rf -- "$dest"
mv -- "$extracted" "$dest"
ln -s -- "$NODE_DIST" "$link"

cat >"$work/receipt.json" <<EOF
{
  "runtime": "node",
  "version": "$NODE_VERSION",
  "platform": "linux-x64",
  "tarball": "$NODE_TARBALL",
  "tarball_url": "$NODE_BASE_URL/$NODE_TARBALL",
  "tarball_sha256": "$actual_sha",
  "checksums_url": "$NODE_BASE_URL/SHASUMS256.txt.asc",
  "signer_fingerprint": "$signer",
  "node_sha256": "$node_sha",
  "npm_tree_sha256": "$npm_sha",
  "fetched_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
mv -- "$work/receipt.json" "$receipt"

installed_ok || die "post-install re-check failed"
say "node v$NODE_VERSION installed at tools/node (receipt tools/node.receipt.json)"
