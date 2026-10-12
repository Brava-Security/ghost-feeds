#!/usr/bin/env bash
# Static release builds for ghost-telemetry-check: the four platforms the tool ships
# to, CGO-free so the binaries run anywhere with no libc dependency, and
# stripped (-s -w) to keep the download small.
# Output: dist/ghost-telemetry-check-<GOOS>-<GOARCH> plus a SHA-256 manifest.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
for GOOS in darwin linux; do
  for GOARCH in arm64 amd64; do
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s -w" -o dist/ghost-telemetry-check-${GOOS}-${GOARCH} .
  done
done
shasum -a 256 dist/*
