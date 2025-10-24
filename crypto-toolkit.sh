#!/bin/bash
# ================================================================
# Copyright © Devin B. Royal – All Rights Reserved
# ================================================================

set -euo pipefail
trap 'echo "[ERROR] $(date): Command failed at line $LINENO" >> crypto-error.log' ERR

# === Globals ===
LOGFILE="crypto-audit.log"
TMPDIR="/tmp/crypto-toolkit"
mkdir -p "$TMPDIR"

# === Platform Detection ===
detect_platform() {
  if command -v apt &>/dev/null; then PKG="apt"
  elif command -v yum &>/dev/null; then PKG="yum"
  elif command -v brew &>/dev/null; then PKG="brew"
  else echo "Unsupported platform"; exit 1
  fi
}

# === Dependency Check ===
check_dependencies() {
  local deps=(openssl oqs-provider curl jq)
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
      echo "Missing dependency: $dep"
      install_dependency "$dep"
    fi
  done
}

install_dependency() {
  case $PKG in
    apt) sudo apt install -y "$1" ;;
    yum) sudo yum install -y "$1" ;;
    brew) brew install "$1" ;;
  esac
}

# === Entropy Validation ===
validate_entropy() {
  if [[ $(cat /proc/sys/kernel/random/entropy_avail) -lt 2000 ]]; then
    echo "Low entropy detected. Consider installing haveged."
    exit 1
  fi
}

# === Key Generation ===
generate_key() {
  local algo="$1"
  local outfile="$2"

  case $algo in
    ed25519)
      openssl genpkey -algorithm ED25519 -out "$outfile"
      ;;
    dilithium2)
      openssl genpkey -provider oqsprovider -algorithm dilithium2 -out "$outfile"
      ;;
    kyber512)
      openssl genpkey -provider oqsprovider -algorithm kyber512 -out "$outfile"
      ;;
    sphincs+-sha2-128f-robust)
      openssl genpkey -provider oqsprovider -algorithm sphincs+-sha2-128f-robust -out "$outfile"
      ;;
    falcon512)
      openssl genpkey -provider oqsprovider -algorithm falcon512 -out "$outfile"
      ;;
    *)
      echo "Unsupported algorithm: $algo"
      exit 1
      ;;
  esac

  echo "$(date): Generated $algo key at $outfile" >> "$LOGFILE"
}

# === Certificate Creation ===
create_certificate() {
  local keyfile="$1"
  local certfile="$2"
  openssl req -new -x509 -key "$keyfile" -out "$certfile" -subj "/CN=CryptoToolkit"
  echo "$(date): Created certificate $certfile" >> "$LOGFILE"
}

# === PKCS#7 Packaging ===
bundle_certificates() {
  local certs=("$@")
  local bundle="cert_bundle.p7b"
  openssl crl2pkcs7 -nocrl -certfile "${certs[0]}" -out "$bundle"
  echo "$(date): Bundled certificates into $bundle" >> "$LOGFILE"
}

# === Rollback Mechanism ===
rollback() {
  echo "Rolling back..."
  rm -rf "$TMPDIR"
  echo "$(date): Rollback executed" >> "$LOGFILE"
}

# === CLI Menu ===
interactive_menu() {
  echo "Crypto Toolkit Menu"
  select opt in "Generate Key" "Create Certificate" "Bundle Certs" "Exit"; do
    case $opt in
      "Generate Key")
        read -p "Algorithm: " algo
        read -p "Output file: " outfile
        generate_key "$algo" "$outfile"
        ;;
      "Create Certificate")
        read -p "Key file: " keyfile
        read -p "Cert file: " certfile
        create_certificate "$keyfile" "$certfile"
        ;;
      "Bundle Certs")
        read -p "Cert files (space-separated): " -a certs
        bundle_certificates "${certs[@]}"
        ;;
      "Exit") break ;;
    esac
  done
}

# === Main Execution ===
main() {
  detect_platform
  check_dependencies
  validate_entropy

  if [[ "$1" == "--interactive" ]]; then
    interactive_menu
  else
    echo "Use --interactive for menu or pass flags for automation."
  fi
}

main "$@"
