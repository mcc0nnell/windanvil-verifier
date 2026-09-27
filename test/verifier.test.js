// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { verifyAssuranceRecordDigest } from "windanvil-assurance-record";
import {
  verifyCosignProvenance,
  verifySupplyChainBundle,
} from "../index.js";

const ARTIFACT = "a".repeat(64);
const SOURCE = "b".repeat(64);
const SOURCE_URI = "git+https://github.com/apache/maven";

function provenance(artifact = ARTIFACT, source = SOURCE) {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "example", digest: { sha256: artifact } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        resolvedDependencies: [
          { uri: SOURCE_URI, digest: { sha256: source } },
        ],
      },
    },
  };
}
function bundle(overrides = {}) {
  return {
    artifact: { kind: "oci_artifact", name: "example.invalid/app", digest: ARTIFACT },
    expectedSource: { uri: SOURCE_URI, digest: SOURCE },
    provenance: provenance(),
    sboms: [{ bomFormat: "CycloneDX", specVersion: "1.6", components: [] }],
    verification: { provenanceSignature: true },
    generatedAt: "2026-09-27T03:00:00Z",
    ...overrides,
  };
}

test("complete independently verified evidence passes", () => {
  const result = verifySupplyChainBundle(bundle());
  assert.equal(result.verdict, "PASS");
  assert.equal(result.assertions.length, 5);
  assert.equal(verifyAssuranceRecordDigest(result.record), true);
  assert.deepEqual(result.record.evidence.artifactDigests, [`sha256:${ARTIFACT}`]);
});

test("missing signature verification blocks instead of passing", () => {
  const input = bundle();
  delete input.verification;
  const result = verifySupplyChainBundle(input);
  assert.equal(result.verdict, "BLOCKED");
  assert.match(result.reason, /provenance_signature/);
});
test("provenance bound to a different artifact fails", () => {
  const result = verifySupplyChainBundle(bundle({
    provenance: provenance("c".repeat(64), SOURCE),
  }));
  assert.equal(result.verdict, "FAIL");
  assert.match(result.reason, /artifact_bound/);
});

test("unrecognized SBOM blocks", () => {
  const result = verifySupplyChainBundle(bundle({ sboms: [{ hello: "world" }] }));
  assert.equal(result.verdict, "BLOCKED");
  assert.match(result.reason, /sbom_present/);
});

test("cosign verification uses the statement it actually verified", () => {
  const payload = Buffer.from(JSON.stringify(provenance())).toString("base64");
  const runner = (_bin, args) => {
    assert.equal(args[0], "verify-attestation");
    return JSON.stringify([{ payload }]);
  };
  const result = verifyCosignProvenance({
    reference: "registry.invalid/app@sha256:" + ARTIFACT,
    certificateIdentity: "https://gitlab.example/project/.gitlab-ci.yml@refs/heads/main",
    certificateIssuer: "https://gitlab.com",
    runner,
  });
  assert.equal(result.verified, true);
  assert.equal(result.statement.subject[0].digest.sha256, ARTIFACT);
});

test("missing cosign is a blocked capability, not a failed signature", () => {
  const error = Object.assign(new Error("spawn cosign ENOENT"), { code: "ENOENT" });
  const result = verifyCosignProvenance({
    reference: "registry.invalid/app@sha256:" + ARTIFACT,
    certificateIdentity: "https://gitlab.example/project/.gitlab-ci.yml@refs/heads/main",
    certificateIssuer: "https://gitlab.com",
    runner: () => { throw error; },
  });
  assert.equal(result.verified, null);
  assert.match(result.reason, /unavailable/);
});

test("openCode source-provenance report binds repository commit", () => {
  const revision = "c".repeat(40);
  const openCode = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "example", digest: { sha256: ARTIFACT } }],
    predicateType: "https://gitlab.opencode.de/open-code/badgebackend/source-provenance-attestation-service/schema/golang/v1/source-provenance-report",
    predicate: {
      version: "1.1.0",
      sourceDefinition: {
        sourceControl: {
          commit: { uri: "https://gitlab.opencode.de/example/project", hash: revision },
        },
      },
    },
  };
  const result = verifySupplyChainBundle(bundle({
    expectedSource: { uri: "https://gitlab.opencode.de/example/project", revision },
    provenance: openCode,
  }));
  assert.equal(result.verdict, "PASS");
});

test("Cosign public-key mode matches the openCode verification boundary", () => {
  const payload = Buffer.from(JSON.stringify(provenance())).toString("base64");
  const runner = (_bin, args) => {
    assert.deepEqual(args.slice(0, 5), [
      "verify-attestation", "--key", "./cosign.pub", "--insecure-ignore-tlog", "--type",
    ]);
    return JSON.stringify([{ payload }]);
  };
  const result = verifyCosignProvenance({
    reference: "registry.invalid/app@sha256:" + ARTIFACT,
    publicKey: "./cosign.pub",
    ignoreTransparencyLog: true,
    predicateType: "https://gitlab.opencode.de/example/source-provenance",
    runner,
  });
  assert.equal(result.verified, true);
});
