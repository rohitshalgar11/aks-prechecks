#!/usr/bin/env bash
# Installs whatever is missing on the runner. If you bake these into your self-hosted
# runner image, this script just verifies them and returns in a second.
set -euo pipefail

KUBENT_VERSION="${KUBENT_VERSION:-0.7.3}"
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"
[ -n "${GITHUB_PATH:-}" ] && echo "$BIN" >> "$GITHUB_PATH"

need() { command -v "$1" >/dev/null 2>&1; }

# az CLI: needs root to install, so it must be in the runner image
if ! need az; then
  echo "::error::az CLI is missing. Bake it into the runner image (https://aka.ms/InstallAzureCLIDeb)."
  exit 1
fi

# kubectl + kubelogin (no root needed)
if ! need kubectl || ! need kubelogin; then
  echo "Installing kubectl and kubelogin"
  az aks install-cli --install-location "$BIN/kubectl" --kubelogin-install-location "$BIN/kubelogin" >/dev/null
fi

# kubent
if ! need kubent; then
  echo "Installing kubent $KUBENT_VERSION"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/kubent.tgz" \
    "https://github.com/doitintl/kube-no-trouble/releases/download/${KUBENT_VERSION}/kubent-${KUBENT_VERSION}-linux-amd64.tar.gz"
  tar -xzf "$tmp/kubent.tgz" -C "$tmp"
  install -m 0755 "$tmp/kubent" "$BIN/kubent"
  rm -rf "$tmp"
fi

# Python deps in a venv (avoids PEP 668 "externally managed" errors on newer Ubuntu)
VENV="${RUNNER_TEMP:-/tmp}/precheck-venv"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r "$(dirname "$0")/requirements.txt"
[ -n "${GITHUB_PATH:-}" ] && echo "$VENV/bin" >> "$GITHUB_PATH"

echo "Tool versions:"
az version --query '"azure-cli"' -o tsv | sed 's/^/  az /'
kubectl version --client -o yaml | grep gitVersion | sed 's/^ */  kubectl /'
kubelogin --version 2>/dev/null | head -n2 | tail -n1 | sed 's/^/  kubelogin /' || true
kubent --version 2>&1 | head -n1 | sed 's/^/  kubent /'
"$VENV/bin/python" --version | sed 's/^/  /'
