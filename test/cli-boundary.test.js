// SPDX-License-Identifier: Apache-2.0
// CLI boundary tests. The positive case uses a fake, local Cosign executable:
// it proves CLI wiring, not cryptographic validity or signer identity.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";

const SCRIPT = resolve("cli.js");
const ARTIFACT = "a".repeat(64);
const SOURCE = "b".repeat(64);
const URI = "git+https://example.invalid/owned";
const NAME = "registry.example.invalid/app";
const REFERENCE = `${NAME}@sha256:${ARTIFACT}`;
const statement = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: NAME, digest: { sha256: ARTIFACT } }],
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      resolvedDependencies: [{ uri: URI, digest: { sha256: SOURCE } }],
    },
  },
};

function bundle(patch = {}) {
  return {
    artifact: { name: NAME, digest: ARTIFACT },
    expectedSource: { uri: URI, digest: SOURCE },
    provenance: statement,
    sboms: [{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: { component: { version: `sha256:${ARTIFACT}` } },
    }],
    ...patch,
  };
}

function runCase(input, flags = [], fakeCosignOutput = null, fakeCosignExitCode = 0) {
  const dir = mkdtempSync(join(tmpdir(), "windanvil-cli-trust-"));
  try {
    const inputPath = join(dir, "bundle.json");
    writeFileSync(inputPath, JSON.stringify(input));
    const env = { ...process.env };
    if (fakeCosignOutput !== null) {
      const fakeExecutable = join(dir, "cosign");
      const responseFile = join(dir, "response.json");
      // The mock refuses a missing operator key, expected predicate, or JSON mode.
      // It is ONLY a test double, not a real signature verifier.
      writeFileSync(responseFile, JSON.stringify(fakeCosignOutput));
      writeFileSync(fakeExecutable,
        '#!/bin/sh\n' +
        'case " $* " in *" --key /operator/trusted.pub "*) ;; *) exit 81;; esac\n' +
        'case " $* " in *" --type slsaprovenance "*) ;; *) exit 82;; esac\n' +
        'case " $* " in *" --output json "*) ;; *) exit 83;; esac\n' +
        'cat "$WINDANVIL_FAKE_COSIGN_RESPONSE"\n' +
        'exit "$WINDANVIL_FAKE_COSIGN_EXIT"\n', { mode: 0o755 });
      env.PATH = dir + delimiter + process.env.PATH;
      env.WINDANVIL_FAKE_COSIGN_RESPONSE = responseFile;
      env.WINDANVIL_FAKE_COSIGN_EXIT = String(fakeCosignExitCode);
    }
    const res = spawnSync(process.execPath, [SCRIPT, "verify", inputPath, ...flags], {
      encoding: "utf8", env, timeout: 15000,
    });
    return {
      status: res.status,
      output: res.stdout.trim() ? JSON.parse(res.stdout) : null,
      stderr: res.stderr,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("missing signer evidence is BLOCKED", () => {
  const result = runCase(bundle());
  assert.equal(result.status, 2);
  assert.equal(result.output?.verdict, "BLOCKED");
});

test("input-supplied signature approval cannot create a CLI PASS", () => {
  const result = runCase(bundle({ verification: { provenanceSignature: true } }));
  assert.equal(result.status, 2);
  assert.equal(result.output?.verdict, "BLOCKED");
  assert.equal(result.output?.assertions.find((x) => x.id === "provenance_signature")?.verdict, "BLOCKED");
});

test("input-supplied policy reduction cannot disable required assertions", () => {
  const result = runCase(bundle({ requiredAssertions: ["provenance_present"] }));
  assert.equal(result.status, 2);
  assert.equal(result.output?.verdict, "BLOCKED");
  assert.equal(result.output?.assertions.length, 6);
});

test("bundled public key, bypass flags and executable path cannot grant trust", () => {
  const result = runCase(bundle({
    cosign: {
      reference: REFERENCE,
      publicKey: "/tmp/attacker.pub",
      ignoreTransparencyLog: true,
      cosign: "/bin/true",
    },
    verification: { provenanceSignature: true },
    requiredAssertions: ["provenance_present"],
  }));
  assert.equal(result.status, 2);
  assert.equal(result.output?.verdict, "BLOCKED");
});

test("reference mismatch BLOCKED even when a trusted key flag exists", () => {
  const result = runCase(bundle({
    cosign: { reference: `${NAME}@sha256:${"c".repeat(64)}` },
  }), ["--trusted-public-key", "/operator/trusted.pub"]);
  assert.equal(result.status, 2);
  assert.equal(result.output?.verdict, "BLOCKED");
  assert.match(result.output?.verification?.provenanceSignatureReason, /reference must match/);
});

test("unexpected or incomplete trust flags return CLI usage error", () => {
  for (const flags of [
    ["--bogus"],
    ["--trusted-certificate-identity", "operator@example"],
    ["--trusted-public-key", "/trusted.pub", "--trusted-certificate-issuer", "https://issuer"],
    ["--ignore-transparency-log"],
  ]) {
    const result = runCase(bundle(), flags);
    assert.equal(result.status, 64);
    assert.equal(result.output, null);
  }
});

test("operator trust flag permits a mocked Cosign-verified valid statement", () => {
  const payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  const result = runCase(bundle({
    cosign: { reference: REFERENCE, cosign: "/bin/false" },
  }), ["--trusted-public-key", "/operator/trusted.pub"], [{ payload }]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output?.verdict, "PASS");
  assert.equal(result.output?.assertions.find((x) => x.id === "provenance_signature")?.verdict, "PASS");
});

test("mocked Cosign statement must bind the expected artifact", () => {
  const wrong = {
    ...statement,
    subject: [{ name: NAME, digest: { sha256: "f".repeat(64) } }],
  };
  const payload = Buffer.from(JSON.stringify(wrong)).toString("base64");
  const result = runCase(bundle({ cosign: { reference: REFERENCE } }),
    ["--trusted-public-key", "/operator/trusted.pub"], [{ payload }]);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.output?.verdict, "FAIL");
});

const OPERATOR_KEY = ["--trusted-public-key", "/operator/trusted.pub"];
function mockedAttestation(signedStatement = statement) {
  return [{ payload: Buffer.from(JSON.stringify(signedStatement)).toString("base64") }];
}

test("all six mandatory assertion IDs remain present despite empty caller policy", () => {
  const result = runCase(bundle({
    requiredAssertions: [],
    cosign: { reference: REFERENCE },
  }), OPERATOR_KEY, mockedAttestation());
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.output.assertions.map((x) => x.id), [
    "provenance_present", "artifact_bound", "source_bound",
    "sbom_present", "sbom_artifact_bound", "provenance_signature",
  ]);
});

test("invalid source binding in a mocked verified statement must FAIL", () => {
  const wrong = {
    ...statement,
    predicate: {
      buildDefinition: { resolvedDependencies: [
        { uri: "git+https://example.invalid/other", digest: { sha256: SOURCE } },
      ] },
    },
  };
  const result = runCase(bundle({ cosign: { reference: REFERENCE } }),
    OPERATOR_KEY, mockedAttestation(wrong));
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.output.verdict, "FAIL");
  assert.equal(result.output.assertions.find((x) => x.id === "source_bound")?.verdict, "FAIL");
});

test("missing SBOM must BLOCK even under mocked valid signed provenance", () => {
  const result = runCase(bundle({
    sboms: [], cosign: { reference: REFERENCE },
  }), OPERATOR_KEY, mockedAttestation());
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.verdict, "BLOCKED");
  assert.equal(result.output.assertions.find((x) => x.id === "sbom_present")?.verdict, "BLOCKED");
});

test("incorrect SBOM artifact digest must FAIL after mocked signature proof", () => {
  const result = runCase(bundle({
    cosign: { reference: REFERENCE },
    sboms: [{
      bomFormat: "CycloneDX", specVersion: "1.6",
      metadata: { component: { version: `sha256:${"c".repeat(64)}` } },
    }],
  }), OPERATOR_KEY, mockedAttestation());
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.output.verdict, "FAIL");
  assert.equal(result.output.assertions.find((x) => x.id === "sbom_artifact_bound")?.verdict, "FAIL");
});

test("Cosign command returning success without a decodable statement cannot PASS", () => {
  for (const output of [[], [{ payload: "??not base64??" }], { message: "success" }]) {
    const result = runCase(bundle({
      cosign: { reference: REFERENCE },
      verification: { provenanceSignature: true },
    }), OPERATOR_KEY, output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(result.output.verdict, "BLOCKED");
    assert.equal(result.output.assertions.find((x) => x.id === "provenance_present")?.verdict, "BLOCKED");
  }
});

test("Cosign command failure cannot PASS even if stdout looks verified", () => {
  const result = runCase(bundle({
    cosign: { reference: REFERENCE },
    verification: { provenanceSignature: true },
  }), OPERATOR_KEY, mockedAttestation(), 21);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.output.verdict, "FAIL");
  assert.equal(result.output.assertions.find((x) => x.id === "provenance_signature")?.verdict, "FAIL");
});

test("mocked successful independent verification overrides bundled false verdict", () => {
  const result = runCase(bundle({
    cosign: { reference: REFERENCE },
    verification: { provenanceSignature: false },
    requiredAssertions: [],
  }), OPERATOR_KEY, mockedAttestation());
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.verdict, "PASS");
});
