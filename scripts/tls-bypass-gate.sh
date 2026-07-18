#!/usr/bin/env bash
# TLS-bypass CI grep gate (CONTRACT.md §6).
#
# §6 is an absolute prohibition on any API surface that bypasses TLS
# verification. The ONLY escape hatch is Builder.customCa(pem), which ADDS a CA
# to the strict verification chain; the §6.1 client-certificate path installs a
# KeyManager and never touches server verification. This gate fails the build if
# a disabled/trust-all TrustManager, a permissive HostnameVerifier, or a
# well-known insecure identifier appears in src/main.
#
# Scope: src/main ONLY. src/test legitimately references TLS types (in-memory
# PKI for the mTLS test) and must not trip its own gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="${SDK_ROOT}/src/main"

if [ ! -d "${TARGET}" ]; then
  echo "OK: no src/main directory yet"
  exit 0
fi

# Patterns:
#  - a trust-all X509TrustManager (empty-body checkServerTrusted)
#  - the well-known insecure identifiers
#  - a permissive HostnameVerifier lambda returning true
#  - any explicit hostnameVerifier override or setter
PATTERN='checkServerTrusted\s*\([^)]*\)\s*(:\s*Unit\s*)?\{\s*\}|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|hostnameVerifier\s*\(|setHostnameVerifier|->\s*true\b'

MATCHES=$(grep -rnE "${PATTERN}" "${TARGET}" 2>/dev/null || true)

if [ -n "${MATCHES}" ]; then
  echo "FAIL: found a TLS-bypass pattern in src/main"
  echo "${MATCHES}"
  exit 1
fi

echo "OK: no TLS-bypass patterns found in src/main"
