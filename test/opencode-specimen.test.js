// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import {
  digestOf,
  verifyAssuranceRecordDigest,
} from "windanvil-assurance-record";
import { unwrapStatement } from "../index.js";

const specimen = new URL("../specimens/opencode-source-provenance/", import.meta.url);
const readJson = (name) =>
  JSON.parse(readFileSync(new URL(name, specimen), "utf8"));

test("frozen openCode specimen remains internally bound", () => {
  const bundle = readJson("bundle.json");
  const result = readJson("result.json");
  const record = readJson("assurance-record.json");
  const verified = readJson("verified-attestation.json");
  const sbom = readJson("sbom.cdx.json");
  const statement = unwrapStatement(verified);
  assert.equal(result.verdict, "PASS");
  assert.equal(record.verdict.value, "PASS");
  assert.equal(verifyAssuranceRecordDigest(record), true);
  assert.deepEqual(result.record, record);

  assert.equal(
    digestOf(statement),
    result.evidenceDigests.provenance,
  );
  assert.equal(
    digestOf(sbom),
    result.evidenceDigests.sboms[0],
  );
  assert.equal(
    digestOf(result.verification),
    result.evidenceDigests.verification,
  );
  assert.equal(result.verification.provenanceSignature, true);
  assert.equal(bundle.verification.publicKeySha256, result.verification.publicKeySha256);
});
