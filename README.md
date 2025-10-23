# Crypto Toolkit - Enterprise Bash CLI

**Copyright © 2025 Devin B. Royal. All Rights Reserved.**

## Overview

Crypto Toolkit is a modular, enterprise-grade Bash CLI suite for classical and post-quantum cryptography (PQC). It provides:

- RSA key generation + self-signed certificates
- EdDSA (Ed25519) key generation
- PQC key generation (Dilithium, Kyber, etc.) via OpenSSL liboqs provider
- PKCS#7 bundle creation and signature verification
- Modular CLI wrapper with interactive and automated modes
- Audit manifest generation with SHA-256 checksums
- Python and Java helper stubs for enterprise integration
- Integrated dependency and environment validation
- Optional liboqs and oqs-provider compilation

This toolkit is designed for secure, auditable deployments in production or lab environments.

---

## Features

- **Modular CLI commands**: Run standalone commands for key generation, signing, verification, and manifest creation.
- **Enterprise-ready logging**: Every action is logged with UTC timestamps; rollback actions are tracked for error handling.
- **Dependency handling**: Automatically checks for system dependencies (OpenSSL 3.x, Python 3, Java 11+, Maven) and optionally installs missing packages.
- **Cross-platform support**: Works on Linux, macOS, and WSL with appropriate package manager detection.
- **Interactive or automated modes**: Use prompts or `--yes`, `--silent`, `--dry-run` for CI/CD integration.
- **Secure defaults**: Root-owned directories, restricted permissions, entropy verification, and cryptographic best practices.

---

## Installation

1. Save the installer:

```bash
wget https://yourhost/crypto_toolkit_installer.sh
chmod +x crypto_toolkit_installer.sh
Run the installer:
sudo ./crypto_toolkit_installer.sh
Optional: install missing dependencies automatically:
sudo ./crypto_toolkit_installer.sh --install-deps --yes
Optional: dry-run mode to preview actions:
sudo ./crypto_toolkit_installer.sh --dry-run
Usage
After installation, you can run the interactive CLI:
sudo /opt/crypto-suite/bin/cryptocli
Or call specific functions via Bash scripting:
# Generate RSA keypair
sudo /opt/crypto-suite/crypto_toolkit_installer.sh
Directory Structure
/opt/crypto-suite/
├── bin/        -> CLI launcher and helper scripts
├── lib/        -> Optional compiled libraries (liboqs builds)
├── python/     -> Python helper stubs and venv (extendable)
├── java/       -> Java helper stubs
├── conf/       -> Policy and configuration files
├── logs/       -> Audit logs
├── manifests/  -> Generated manifests and checksums
Python & Java Helpers
Python: python/crypto_helper.py
Java: java/CryptoHelper.java
These stubs provide skeletons for Ed25519 key generation and can be extended for PQC libraries.
Security & Compliance
Uses root-owned, restricted directories for key storage
All keys and bundles are logged with SHA-256 checksums
Supports PQC providers via OpenSSL liboqs
Optional rollback for failed installation or errors
Contributing
This is an enterprise, proprietary toolkit. Contributions are restricted and require code review and compliance validation.
Support
Contact: Devin B. Royal
Email: paper.in.my.pocket@my.com
Phone: (650)664-0543

