#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

for tool in docker cosign syft node jq; do
  command -v "$tool" >/dev/null || {
    echo "missing required tool: $tool" >&2
    exit 2
  }
done

COMMIT="cce3945b8d30e6d1bd55487f34ebff4bdff0536c"
DIGEST="sha256:06cee1821dcf9ad397f999cf1a4d8b89f2d696da9e52f7b819607fbff1b82664"
IMAGE="registry.opencode.de/l3montree/source-provenance-attestation-service-example"
TAG="$IMAGE:$COMMIT"
REF="$IMAGE@$DIGEST"
SPEC="specimens/opencode-source-provenance"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

docker pull "$TAG" >/dev/null
actual_ref="$(docker image inspect "$TAG" --format '{{index .RepoDigests 0}}')"
actual_digest="${actual_ref##*@}"
test "$actual_digest" = "$DIGEST" || {
  echo "registry tag no longer resolves to expected digest" >&2
  exit 3
}

syft "docker:$REF" -o cyclonedx-json > "$tmp/sbom.cdx.json"

jq --slurpfile sbom "$tmp/sbom.cdx.json"   '.sboms=$sbom | .generatedAt=(now|todateiso8601)'   "$SPEC/bundle.json" > "$tmp/bundle.json"

PATH="$(dirname "$(command -v cosign)"):$PATH"   node cli.js verify "$tmp/bundle.json" > "$tmp/result.json"

jq -e '.verdict == "PASS"' "$tmp/result.json" >/dev/null
jq '{verdict, reason, recordDigest: .record.digest}' "$tmp/result.json"
