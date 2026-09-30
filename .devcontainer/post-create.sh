#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Named volumes are initialized by Docker as root on some hosts.
if command -v sudo >/dev/null 2>&1; then
    sudo chown -R "$(id -u):$(id -g)" \
        "$repo_root/target" \
        "$HOME/.cargo" \
        "$HOME/.cache/yarn" 2>/dev/null || true
fi

expected_yarn_version="1.22.19"
if [[ "$(yarn --version)" != "$expected_yarn_version" ]]; then
    corepack prepare "yarn@${expected_yarn_version}" --activate
fi

echo "Installing workspace dependencies..."
yarn install --frozen-lockfile
npm ci --prefix vscode

install_cargo_tool() {
    local command_name="$1"
    shift

    if ! command -v "$command_name" >/dev/null 2>&1; then
        cargo install "$@"
    fi
}

echo "Installing Rust development tools..."
install_cargo_tool wasm-pack wasm-pack --version '^0.13' --locked
install_cargo_tool cargo-watch cargo-watch --version '^8' --locked
install_cargo_tool cargo-llvm-cov cargo-llvm-cov --locked

echo
echo "FlowScope devcontainer ready. Try:"
echo "  just build"
echo "  just test"
echo "  just dev"
