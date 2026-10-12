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
    sboms: [{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: { component: { type: "container", version: `sha256:${ARTIFACT}` } },
      components: [],
    }],
    verification: { provenanceSignature: true },
    generatedAt: "2026-09-27T03:00:00Z",
    ...overrides,
  };
}

test("complete independently verified evidence passes", () => {
  const result = verifySupplyChainBundle(bundle());
  assert.equal(result.verdict, "PASS");
  assert.equal(result.assertions.length, 6);
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

test("CycloneDX bound to another artifact fails", () => {
  const input = bundle();
  input.sboms[0].metadata.component.version = "sha256:" + "d".repeat(64);
  const result = verifySupplyChainBundle(input);
  assert.equal(result.verdict, "FAIL");
  assert.match(result.reason, /sbom_artifact_bound/);
});

test("evidence digests bind provenance, SBOM, and verification metadata", () => {
  const input = bundle();
  const result = verifySupplyChainBundle(input);
  assert.ok(result.evidenceDigests.provenance);
  assert.equal(result.evidenceDigests.sboms.length, 1);
  assert.ok(result.evidenceDigests.verification);
  const mutated = bundle();
  mutated.sboms[0].components.push({ type: "library", name: "different" });
  const changed = verifySupplyChainBundle(mutated);
  assert.notEqual(changed.evidenceDigests.sboms[0], result.evidenceDigests.sboms[0]);
  assert.notEqual(changed.record.digest, result.record.digest);
});

test("SLSA source URI alone cannot count as immutable source binding", () => {
  const input = bundle({ expectedSource: { uri: SOURCE_URI } });
  const result = verifySupplyChainBundle(input);
  assert.equal(result.verdict, "FAIL");
  assert.equal(result.assertions.find((x) => x.id === "source_bound")?.verdict, "FAIL");
});

test("SLSA source revision cannot be silently ignored", () => {
  const input = bundle({
    expectedSource: { uri: SOURCE_URI, digest: SOURCE, revision: "c".repeat(40) },
  });
  const result = verifySupplyChainBundle(input);
  assert.equal(result.verdict, "FAIL");
  assert.equal(result.assertions.find((x) => x.id === "source_bound")?.verdict, "FAIL");
});

test("SLSA source revision passes only when attested material binds it", () => {
  const revision = "c".repeat(40);
  const withRevision = provenance();
  withRevision.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = revision;
  const input = bundle({
    expectedSource: { uri: SOURCE_URI, digest: SOURCE, revision },
    provenance: withRevision,
  });
  assert.equal(verifySupplyChainBundle(input).verdict, "PASS");
  const wrongDigest = bundle({
    expectedSource: { uri: SOURCE_URI, digest: "e".repeat(64), revision },
    provenance: withRevision,
  });
  assert.equal(verifySupplyChainBundle(wrongDigest).verdict, "FAIL");
});

test("openCode source commit refuses missing revision or competing extra digest", () => {
  const rev = "c".repeat(40);
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ digest: { sha256: ARTIFACT } }],
    predicateType: "https://gitlab.opencode.de/example/source-provenance",
    predicate: { sourceDefinition: { sourceControl: {
      commit: { uri: "https://example.invalid/repo", hash: rev },
    } } },
  };
  const expected = { uri: "https://example.invalid/repo", revision: rev };
  assert.equal(verifySupplyChainBundle(bundle({
    provenance: statement, expectedSource: expected,
  })).verdict, "PASS");
  assert.equal(verifySupplyChainBundle(bundle({
    provenance: statement, expectedSource: { uri: expected.uri },
  })).verdict, "FAIL");
  assert.equal(verifySupplyChainBundle(bundle({
    provenance: statement,
    expectedSource: { ...expected, digest: "sha256:" + "b".repeat(64) },
  })).verdict, "FAIL");
});

test("SBOM evidence digest includes prototype-named JSON fields", () => {
  const original = bundle().sboms[0];
  const first = JSON.parse(JSON.stringify(original));
  const second = JSON.parse(JSON.stringify(original));
  Object.defineProperty(first, "__proto__", { value: { marker: "A" }, enumerable: true });
  Object.defineProperty(second, "__proto__", { value: { marker: "B" }, enumerable: true });
  const a = verifySupplyChainBundle(bundle({ sboms: [first] }));
  const b = verifySupplyChainBundle(bundle({ sboms: [second] }));
  assert.equal(a.verdict, "PASS");
  assert.equal(b.verdict, "PASS");
  assert.notEqual(a.evidenceDigests.sboms[0], b.evidenceDigests.sboms[0]);
  assert.notEqual(a.record.digest, b.record.digest);
});
