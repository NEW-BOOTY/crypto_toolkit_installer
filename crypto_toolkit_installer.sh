#!/usr/bin/env bash
# ================================================================
# crypto_toolkit_installer.sh
# Enterprise Bash CLI Cryptographic Toolkit Installer + CLI
# ================================================================
# Copyright © 2025 Devin B. Royal.
# All rights reserved.
#
# PURPOSE:
#   Install and manage a hybrid classical + post-quantum cryptographic
#   toolkit. Provides modular CLI commands, dependency installation,
#   extreme error handling, audit logging, and helper stubs for Java/Python.
#
# USAGE:
#   sudo ./crypto_toolkit_installer.sh [--install-deps] [--silent] [--dry-run]
#   sudo ./crypto_toolkit_installer.sh --help
#
# ARCHITECTURE SUMMARY (commented-out, high-level)
# ----------------------------------------------------------------
# - CLI Entrypoint (this script)
# - /opt/crypto-suite/
#     - bin/            -> helper executables (shims)
#     - lib/            -> optional compiled libs (liboqs builds)
#     - python/         -> python helper scripts & venv
#     - java/           -> java helper stubs / build files
#     - conf/           -> config files (policy.json)
#     - logs/           -> runtime logs
#     - manifests/      -> generated manifests and checksums
# - Dependencies: openssl (3.x), liboqs (optional), python3 + venv, java (11+), maven (optional)
# - Crypto Engines:
#     - Classical: OpenSSL (RSA, Ed25519)
#     - PQC: liboqs (Kyber, Dilithium, SPHINCS+, Falcon) via provider
# - Packaging: PKCS#7 using openssl smime; optional zip bundles with manifests
# - Security: files written root:root, restricted perms; detailed audit logging
# ----------------------------------------------------------------
# LIMITATIONS:
# - Script orchestrates and calls vetted tools; it does not implement crypto primitives.
# - Building liboqs and PQC providers is destructive to disk (compilation) and requires tools.
# - Production deployment should be reviewed by your security team / code signing process.
# ================================================================

set -euo pipefail
IFS=$'\n\t'

## -------------------------
## Configuration (tweakable)
## -------------------------
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/crypto-suite}"
BIN_DIR="${INSTALL_PREFIX}/bin"
LIB_DIR="${INSTALL_PREFIX}/lib"
PY_DIR="${INSTALL_PREFIX}/python"
JAVA_DIR="${INSTALL_PREFIX}/java"
CONF_DIR="${INSTALL_PREFIX}/conf"
LOG_DIR="${INSTALL_PREFIX}/logs"
MANIFEST_DIR="${INSTALL_PREFIX}/manifests"
TMP_ROOT="${TMP_ROOT:-/tmp/crypto_toolkit.$$}"
LOG_FILE="${LOG_DIR}/installer.log"
CONFIG_FILE="${CONF_DIR}/policy.json"
DEFAULT_PROVIDER_CHECK_CMD="openssl provider -list 2>/dev/null || true"

# Defaults for cryptographic algorithms
DEFAULT_RSA_KEY_SIZE=4096
DEFAULT_EDDSA_ALG="ed25519"
DEFAULT_PQC_KEM="kyber512"
DEFAULT_PQC_SIG="dilithium2"

# Execution flags
DRY_RUN=false
SILENT=false
AUTO_YES=false

# For CIs, you may pass --yes to auto accept installing dependencies.
while [ $# -gt 0 ]; do
  case "$1" in
    --install-deps) INSTALL_DEPS=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --silent) SILENT=true; shift ;;
    --yes|--auto|--assume-yes) AUTO_YES=true; shift ;;
    --help|-h) echo "Usage: sudo $0 [--install-deps] [--dry-run] [--silent] [--yes]"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# -------------------------
# Logging helpers
# -------------------------
mkdir -p "${LOG_DIR}" || true
touch "${LOG_FILE}" || true
exec 3>>"${LOG_FILE}"

log() {
  local lvl="${1:-INFO}"
  local msg="${2:-}"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "${ts} ${lvl} ${msg}" | tee -a "${LOG_FILE}" >&3
}

fatal() {
  log "FATAL" "$1"
  echo "FATAL: $1" >&2
  exit 2
}

info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
debug() { log "DEBUG" "$1"; }

# -------------------------
# Error trapping & rollback
# -------------------------
ROLLBACK_ACTIONS=()
rollback() {
  warn "Running rollback actions..."
  for act in "${ROLLBACK_ACTIONS[@]}"; do
    eval "${act}" || warn "Rollback action failed: ${act}"
  done
  warn "Rollback complete."
}
onexit() {
  rc=$?
  if [ $rc -ne 0 ]; then
    warn "Script exited with code ${rc}. Initiating rollback."
    rollback
  fi
  info "Installer exit status: ${rc}"
}
trap onexit EXIT
trap 'fatal "Interrupted by signal";' INT TERM

# -------------------------
# Utility helpers
# -------------------------
confirm() {
  if $AUTO_YES || $SILENT; then
    return 0
  fi
  local prompt="$1"
  read -rp "${prompt} [y/N]: " ans
  case "${ans}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_dir() {
  local d="$1"
  if [ ! -d "$d" ]; then
    if $DRY_RUN; then
      info "DRY-RUN: mkdir -p $d"
    else
      mkdir -p "$d"
      ROLLBACK_ACTIONS+=("rm -rf \"$d\"")
      info "Created $d"
    fi
  fi
}

which_or_die() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fatal "Required command not found: $cmd"
  fi
}

# -------------------------
# Platform detection
# -------------------------
OS="$(uname -s)"
PLATFORM=""
PKG_CMD=""
PKG_INSTALL_CMD=""
PKG_UPDATE_CMD=""

detect_platform() {
  case "${OS}" in
    Darwin)
      PLATFORM="macos"
      if command -v brew >/dev/null 2>&1; then
        PKG_CMD="brew"
        PKG_INSTALL_CMD="brew install"
        PKG_UPDATE_CMD="brew update"
      else
        PKG_CMD="none"
      fi
      ;;
    Linux)
      PLATFORM="linux"
      if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "${ID_LIKE:-}" =~ debian ]] || [[ "${ID:-}" =~ (debian|ubuntu) ]]; then
          PKG_CMD="apt"
          PKG_INSTALL_CMD="apt-get install -y"
          PKG_UPDATE_CMD="apt-get update -y"
        elif [[ "${ID_LIKE:-}" =~ rhel ]] || [[ "${ID:-}" =~ (rhel|centos|fedora|rocky|almalinux) ]]; then
          PKG_CMD="yum"
          PKG_INSTALL_CMD="yum install -y"
          PKG_UPDATE_CMD="yum makecache"
        else
          PKG_CMD="unknown"
        fi
      fi
      # detect WSL
      if grep -qi microsoft /proc/version 2>/dev/null || grep -qi wsl /proc/version 2>/dev/null; then
        PLATFORM="wsl"
      fi
      ;;
    *)
      PLATFORM="unknown"
      ;;
  esac
  info "Platform detected: ${PLATFORM} (uname=${OS})"
}

# -------------------------
# Dependency validation
# -------------------------
REQUIRED_CMDS=(bash sh openssl git curl tar gzip shasum sed awk python3 java javac)
OPTIONAL_CMDS=(mvn convert sips pdfunite gs)

validate_dependencies() {
  info "Validating required commands..."
  local missing=()
  for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    warn "Missing required commands: ${missing[*]}"
  else
    info "All required base commands present."
  fi

  # Check OpenSSL version
  if command -v openssl >/dev/null 2>&1; then
    local ver
    ver=$(openssl version 2>/dev/null || true)
    info "OpenSSL version: ${ver}"
  else
    missing+=("openssl")
  fi

  # Check for liboqs provider presence (best-effort)
  local oqs_ok=false
  if command -v openssl >/dev/null 2>&1; then
    if openssl provider -list 2>/dev/null | grep -qi oqs; then
      oqs_ok=true
    fi
  fi
  if $oqs_ok; then
    info "liboqs provider appears available to OpenSSL."
  else
    warn "liboqs / OQS provider not detected in OpenSSL. PQC algorithms will be unavailable until liboqs provider is installed."
  fi

  # Return list of missing via global var
  MISSING_COMMANDS=("${missing[@]:-}")
}

# -------------------------
# Install dependencies
# -------------------------
install_dependencies() {
  detect_platform
  validate_dependencies

  if [ "${#MISSING_COMMANDS[@]}" -eq 0 ] && command -v openssl >/dev/null 2>&1; then
    info "No missing required commands. Skipping package installation."
    return 0
  fi

  if [ "$PKG_CMD" = "none" ] || [ "$PKG_CMD" = "unknown" ]; then
    warn "Automatic package installation is not supported on this platform. Please install these packages manually: ${MISSING_COMMANDS[*]}"
    return 1
  fi

  info "Preparing to install dependencies via ${PKG_CMD}. Missing: ${MISSING_COMMANDS[*]}"
  if ! confirm "Proceed to install missing packages with ${PKG_CMD}?"; then
    warn "User declined to install packages automatically."
    return 1
  fi

  # Update package cache
  if [ -n "${PKG_UPDATE_CMD}" ]; then
    info "Updating package cache..."
    if $DRY_RUN; then
      info "DRY-RUN: ${PKG_UPDATE_CMD}"
    else
      eval "${PKG_UPDATE_CMD}"
    fi
  fi

  # Map missing commands to packages heuristically
  declare -A pkgmap
  pkgmap=(
    [openssl]="openssl"
    [git]="git"
    [curl]="curl"
    [python3]="python3"
    [javac]="openjdk-11-jdk"
    [java]="openjdk-11-jre"
    [mvn]="maven"
    [shasum]="coreutils"
    [tar]="tar"
    [gzip]="gzip"
    [sed]="sed"
    [awk]="gawk"
  )

  to_install=()
  for cmd in "${MISSING_COMMANDS[@]}"; do
    pkg="${pkgmap[$cmd]:-$cmd}"
    to_install+=("${pkg}")
  done

  # Unique list
  IFS=$'\n' read -r -d '' -a to_install < <(printf "%s\n" "${to_install[@]}" | awk '!x[$0]++' && printf '\0')
  info "Installing packages: ${to_install[*]}"
  if $DRY_RUN; then
    info "DRY-RUN: ${PKG_INSTALL_CMD} ${to_install[*]}"
  else
    # Attempt install
    if ! eval "${PKG_INSTALL_CMD} ${to_install[*]}"; then
      warn "Package installation failed. Please install packages manually and re-run."
      return 1
    fi
  fi

  info "Dependency installation complete. Revalidating..."
  validate_dependencies
}

# -------------------------
# Build & install liboqs + oqs-provider (optional)
# -------------------------
build_liboqs_and_provider() {
  info "liboqs build/install requested."
  if ! confirm "Build and install liboqs + OpenSSL oqs-provider (requires git, cmake, build-essentials)?"; then
    warn "Skipping liboqs build as user declined."
    return 1
  fi

  # Ensure build tools
  for b in git cmake make gcc; do
    if ! command -v "$b" >/dev/null 2>&1; then
      fatal "Build dependency missing: $b. Install it before building liboqs."
    fi
  done

  ensure_dir "${LIB_DIR}/build"
  pushd "${LIB_DIR}/build" >/dev/null || fatal "pushd failed"

  # Clone liboqs
  if [ ! -d liboqs ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git liboqs || fatal "git clone liboqs failed"
    ROLLBACK_ACTIONS+=("rm -rf \"${LIB_DIR}/build/liboqs\"")
  fi

  # Build liboqs
  mkdir -p liboqs/build && pushd liboqs/build >/dev/null
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON ..
  make -j"$(nproc || sysctl -n hw.ncpu || echo 2)" || fatal "make liboqs failed"
  sudo make install || fatal "make install liboqs failed"
  popd >/dev/null

  # Build OpenSSL oqs-provider (oqs-provider)
  if [ ! -d oqs-provider ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git oqs-provider || fatal "git clone oqs-provider failed"
    ROLLBACK_ACTIONS+=("rm -rf \"${LIB_DIR}/build/oqs-provider\"")
  fi
  pushd oqs-provider >/dev/null
  # Build and install provider - assumes system OpenSSL dev headers available
  mkdir -p build && cd build
  cmake ..
  make -j"$(nproc || sysctl -n hw.ncpu || echo 2)" || fatal "make oqs-provider failed"
  sudo make install || fatal "make install oqs-provider failed"
  popd >/dev/null

  popd >/dev/null || true
  info "liboqs and oqs-provider install attempted. Please verify 'openssl provider -list' shows oqs provider."
}

# -------------------------
# Initialize install tree
# -------------------------
initialize_tree() {
  info "Initializing installation directories under ${INSTALL_PREFIX}"
  if [ -d "${INSTALL_PREFIX}" ]; then
    info "${INSTALL_PREFIX} already exists."
  else
    ensure_dir "${INSTALL_PREFIX}"
  fi
  ensure_dir "${BIN_DIR}"
  ensure_dir "${LIB_DIR}"
  ensure_dir "${PY_DIR}"
  ensure_dir "${JAVA_DIR}"
  ensure_dir "${CONF_DIR}"
  ensure_dir "${LOG_DIR}"
  ensure_dir "${MANIFEST_DIR}"
  # create default policy file
  if [ ! -f "${CONFIG_FILE}" ]; then
    cat > "${CONFIG_FILE}" <<'JSON'
{
  "policy_name": "Devin B. Royal Crypto Toolkit Policy",
  "default_key_rsa_bits": 4096,
  "default_ed_alg": "ed25519",
  "default_pqc_kem": "kyber512",
  "default_pqc_sig": "dilithium2",
  "audit_log": true,
  "retain_manifests_days": 365
}
JSON
    ROLLBACK_ACTIONS+=("rm -f \"${CONFIG_FILE}\"")
  fi
  info "Directory tree initialized."
}

# -------------------------
# Helper: write audit manifest
# -------------------------
write_manifest() {
  local what="$1"
  local dest="${MANIFEST_DIR}/manifest_$(date -u +%Y%m%dT%H%M%SZ)_${what}.txt"
  {
    echo "manifest: ${what}"
    echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "install_prefix: ${INSTALL_PREFIX}"
    echo "os: ${OS}"
    echo "platform: ${PLATFORM}"
    echo ""
    echo "file checksums:"
    find "${INSTALL_PREFIX}" -type f -maxdepth 4 -print0 | xargs -0 shasum -a 256 2>/dev/null || true
  } > "${dest}"
  chmod 444 "${dest}" || true
  info "Manifest written: ${dest}"
}

# -------------------------
# Crypto operations (wrappers)
# -------------------------
# These functions call underlying tools (OpenSSL, oqs-provider). If provider missing,
# they will abort with a clear message instructing how to install prerequisites.

check_openssl_provider() {
  if command -v openssl >/dev/null 2>&1; then
    if openssl provider -list 2>/dev/null | grep -qi oqs; then
      return 0
    fi
  fi
  return 1
}

gen_rsa_key_and_cert() {
  local outdir="${1:-${INSTALL_PREFIX}/artifacts}"
  local name="${2:-device}"
  local bits="${3:-${DEFAULT_RSA_KEY_SIZE}}"
  ensure_dir "${outdir}"
  info "Generating RSA ${bits}-bit keypair + self-signed cert: ${name}"
  if $DRY_RUN; then
    info "DRY-RUN: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -out ${outdir}/${name}.key.pem"
    info "DRY-RUN: openssl req -new -x509 -key ${outdir}/${name}.key.pem -out ${outdir}/${name}.crt.pem -days 3650 -subj '/CN=${name}'"
    return 0
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -out "${outdir}/${name}.key.pem" || fatal "RSA key gen failed"
  openssl req -new -x509 -key "${outdir}/${name}.key.pem" -out "${outdir}/${name}.crt.pem" -days 3650 -subj "/CN=${name}" || fatal "Creating self-signed cert failed"
  chmod 400 "${outdir}/${name}.key.pem"
  info "RSA key and cert generated at ${outdir}/${name}.key.pem and ${outdir}/${name}.crt.pem"
  write_manifest "rsa_${name}"
}

gen_eddsa_key() {
  local outdir="${1:-${INSTALL_PREFIX}/artifacts}"
  local name="${2:-user}"
  local alg="${3:-${DEFAULT_EDDSA_ALG}}"
  ensure_dir "${outdir}"
  info "Generating EdDSA key (${alg}) for: ${name}"
  if $DRY_RUN; then
    info "DRY-RUN: openssl genpkey -algorithm ${alg} -out ${outdir}/${name}.${alg}.key.pem"
    return 0
  fi
  # OpenSSL 3 supports Ed25519 via 'openssl genpkey -algorithm ed25519'
  openssl genpkey -algorithm "${alg}" -out "${outdir}/${name}.${alg}.key.pem" || fatal "EdDSA gen failed"
  chmod 400 "${outdir}/${name}.${alg}.key.pem"
  info "EdDSA key generated: ${outdir}/${name}.${alg}.key.pem"
  write_manifest "eddsa_${name}"
}

gen_pqc_keypair() {
  local outdir="${1:-${INSTALL_PREFIX}/artifacts}"
  local name="${2:-pqc_user}"
  local scheme="${3:-${DEFAULT_PQC_SIG}}"
  ensure_dir "${outdir}"
  info "Generating PQC signature keypair (scheme=${scheme}) for ${name}"
  if check_openssl_provider; then
    if $DRY_RUN; then
      info "DRY-RUN: openssl genpkey -provider oqs -algorithm ${scheme} -out ${outdir}/${name}.${scheme}.key.pem"
      return 0
    fi
    # Example: openssl genpkey -provider oqs -algorithm dilithium2 -out key.pem
    openssl genpkey -provider oqs -algorithm "${scheme}" -out "${outdir}/${name}.${scheme}.key.pem" || fatal "PQC key generation failed (openssl+oqs)"
    chmod 400 "${outdir}/${name}.${scheme}.key.pem"
    info "PQC keypair generated: ${outdir}/${name}.${scheme}.key.pem"
    write_manifest "pqc_${name}_${scheme}"
  else
    fatal "liboqs provider not available. Please run the script with build_liboqs_and_provider or install liboqs and oqs-provider."
  fi
}

create_pkcs7_bundle() {
  local outdir="${1:-${INSTALL_PREFIX}/artifacts}"
  local name="${2:-bundle}"
  local signer_cert="${3:-}"
  local signer_key="${4:-}"
  local infile="${5:-}"
  ensure_dir "${outdir}"
  if [ -z "${signer_cert}" ] || [ -z "${signer_key}" ]; then
    fatal "create_pkcs7_bundle requires signer_cert and signer_key"
  fi
  info "Creating PKCS#7 bundle (signed) ${name}"
  if $DRY_RUN; then
    info "DRY-RUN: openssl smime -sign -in ${infile} -signer ${signer_cert} -inkey ${signer_key} -out ${outdir}/${name}.p7b -outform DER"
    return 0
  fi
  openssl smime -sign -in "${infile}" -signer "${signer_cert}" -inkey "${signer_key}" -out "${outdir}/${name}.p7b" -outform DER -binary || fatal "PKCS#7 creation failed"
  info "PKCS#7 bundle created: ${outdir}/${name}.p7b"
  write_manifest "pkcs7_${name}"
}

verify_signature() {
  local sigfile="$1"
  local infile="$2"
  info "Verifying signature ${sigfile} on ${infile}"
  if $DRY_RUN; then
    info "DRY-RUN: openssl smime -verify -in ${sigfile} -inform DER -content ${infile} -noverify -purpose any"
    return 0
  fi
  openssl smime -verify -in "${sigfile}" -inform DER -content "${infile}" -noverify -purpose any || fatal "Signature verification failed"
  info "Signature verification OK"
}

# -------------------------
# Java & Python helper stubs
# -------------------------
write_python_helper() {
  ensure_dir "${PY_DIR}"
  local pyfile="${PY_DIR}/crypto_helper.py"
  cat > "${pyfile}" <<'PY'
#!/usr/bin/env python3
"""
crypto_helper.py
Python helper stub for cryptographic operations.
- Uses 'cryptography' for classical primitives (Ed25519, RSA).
- For PQC, expects a 'python-liboqs' binding (not installed by default).
This is a stub to be extended and hardened for enterprise use.
"""
import sys
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception as e:
    print("Required Python 'cryptography' library missing. Install with: pip3 install cryptography", file=sys.stderr)
    sys.exit(2)

def gen_ed25519_keypair(out_path):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(out_path).mkdir(parents=True, exist_ok=True)
    Path(out_path+"/ed25519.key.pem").write_bytes(priv_bytes)
    Path(out_path+"/ed25519.pub.pem").write_bytes(pub_bytes)
    print("Generated ed25519 keypair at", out_path)

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--gen-ed", dest="gen_ed", action="store_true")
    p.add_argument("--out", dest="out", default="/tmp")
    args = p.parse_args()
    if args.gen_ed:
        gen_ed25519_keypair(args.out)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
PY
  chmod 755 "${pyfile}"
  info "Python helper written: ${pyfile}"
  write_manifest "python_helper"
}

write_java_helper() {
  ensure_dir "${JAVA_DIR}"
  local jfile="${JAVA_DIR}/CryptoHelper.java"
  cat > "${jfile}" <<'JAVA'
/*
 * CryptoHelper.java
 * Java helper stub for cryptographic operations.
 * Uses standard Java Security APIs and is intended to be extended to use
 * BouncyCastle provider or other enterprise providers (PKCS#11, KeyStore, HSM).
 *
 * Compile with: javac CryptoHelper.java
 * Run: java CryptoHelper
 */
import java.security.*;
import java.security.spec.*;
import java.io.*;
public class CryptoHelper {
    public static void genEd25519(String outDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();
        try (FileOutputStream fos = new FileOutputStream(outDir + "/ed25519.key.der")) {
            fos.write(sk.getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(outDir + "/ed25519.pub.der")) {
            fos.write(pk.getEncoded());
        }
        System.out.println("Generated Ed25519 pair in " + outDir);
    }
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java CryptoHelper <outDir>");
            System.exit(1);
        }
        genEd25519(args[0]);
    }
}
JAVA
  info "Java helper written: ${jfile}"
  write_manifest "java_helper"
}

# -------------------------
# CLI interactive menu
# -------------------------
show_menu() {
  cat <<'MENU'
Crypto Toolkit - Menu
1) Generate RSA keypair + self-signed cert
2) Generate EdDSA keypair (Ed25519)
3) Generate PQC signature keypair (requires liboqs provider)
4) Create PKCS#7 signed bundle
5) Verify signature
6) Build & install liboqs + oqs-provider (experimental)
7) Write Java and Python helper stubs
8) Install dependencies
9) Exit
MENU
}

interactive() {
  while true; do
    show_menu
    read -rp "Select an option [1-9]: " choice
    case "${choice}" in
      1)
        read -rp "Output directory (default: ${INSTALL_PREFIX}/artifacts): " od
        od="${od:-${INSTALL_PREFIX}/artifacts}"
        read -rp "Name (default: device): " name
        name="${name:-device}"
        gen_rsa_key_and_cert "${od}" "${name}" "${DEFAULT_RSA_KEY_SIZE}"
        ;;
      2)
        read -rp "Output directory (default: ${INSTALL_PREFIX}/artifacts): " od
        od="${od:-${INSTALL_PREFIX}/artifacts}"
        read -rp "Name (default: user): " name
        name="${name:-user}"
        gen_eddsa_key "${od}" "${name}" "${DEFAULT_EDDSA_ALG}"
        ;;
      3)
        read -rp "Output directory (default: ${INSTALL_PREFIX}/artifacts): " od
        od="${od:-${INSTALL_PREFIX}/artifacts}"
        read -rp "Name (default: pqc_user): " name
        name="${name:-pqc_user}"
        read -rp "Scheme (default: ${DEFAULT_PQC_SIG}): " scheme
        scheme="${scheme:-${DEFAULT_PQC_SIG}}"
        gen_pqc_keypair "${od}" "${name}" "${scheme}"
        ;;
      4)
        read -rp "Signer cert path: " sc
        read -rp "Signer key path: " sk
        read -rp "Input file to sign: " infile
        read -rp "Name of bundle: " name
        create_pkcs7_bundle "${INSTALL_PREFIX}/artifacts" "${name}" "${sc}" "${sk}" "${infile}"
        ;;
      5)
        read -rp "Signature file (DER .p7b): " sig
        read -rp "Original file: " orig
        verify_signature "${sig}" "${orig}"
        ;;
      6)
        build_liboqs_and_provider
        ;;
      7)
        write_python_helper
        write_java_helper
        ;;
      8)
        install_dependencies
        ;;
      9)
        info "Exiting."
        break
        ;;
      *)
        echo "Invalid option"
        ;;
    esac
  done
}

# -------------------------
# Entrypoint
# -------------------------
main() {
  info "Starting crypto toolkit installer."
  detect_platform
  initialize_tree
  validate_dependencies

  if [ "${INSTALL_DEPS:-false}" = true ]; then
    install_dependencies || warn "Dependency installation reported issues."
  fi

  # Put a wrapper CLI into BIN_DIR
  local wrapper="${BIN_DIR}/crypto-toolkit"
  cat > "${wrapper}" <<'SH'
#!/usr/bin/env bash
# wrapper entrypoint for Crypto Toolkit
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
exec "${SCRIPT_DIR}/bin/../$(basename "$0")" "$@"
SH
  chmod 755 "${wrapper}" || true

  # Write simple launcher that invokes this script in interactive mode
  local launcher="${BIN_DIR}/cryptocli"
  cat > "${launcher}" <<'SH'
#!/usr/bin/env bash
# Launcher for crypto toolkit interactive CLI
SCRIPTPATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd))/bin/../crypto_toolkit_installer.sh"
if [ -x "$SCRIPTPATH" ]; then
  exec sudo bash "$SCRIPTPATH"
else
  echo "Cannot find toolkit script at $SCRIPTPATH"
  exit 1
fi
SH
  chmod 755 "${launcher}" || true

  # Provide helpful message and drop into interactive unless silent/dry-run
  info "Installation skeleton created under ${INSTALL_PREFIX}"
  write_manifest "install_init"

  if $DRY_RUN; then
    info "DRY-RUN mode: no further actions taken."
    return
  fi

  if ! $SILENT; then
    interactive
  fi

  info "crypto toolkit installer completed."
}

main "$@"
