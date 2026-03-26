#!/usr/bin/env bash
set -euo pipefail

export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin"

if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go not found in PATH."
  echo "Try: export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
  exit 1
fi

echo "Using $(go version)"

echo "Building Linux amd64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ip-lookup .

echo "Cross-compiling Windows amd64 binary..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ip-lookup.exe .

echo "Build complete:"
ls -lh ip-lookup ip-lookup.exe
