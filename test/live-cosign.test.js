// SPDX-License-Identifier: Apache-2.0
// Opt-in online interoperability smoke test: no image layers are downloaded.
// Enable with WINDANVIL_LIVE_COSIGN=1 node --test test/live-cosign.test.js
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const enabled = process.env.WINDANVIL_LIVE_COSIGN === "1";
const SPECIMEN = resolve("specimens/opencode-source-provenance");
const predicateType = "https://gitlab.opencode.de/open-code/badgebackend/source-provenance-attestation-service/schema/source-provenance-report-v1";

function verifyWith(key) {
  const args = [
    resolve("cli.js"), "verify", resolve(SPECIMEN, "bundle.json"),
    "--trusted-public-key", key,
    "--predicate-type", predicateType,
    "--ignore-transparency-log",
  ];
  const result = spawnSync(process.execPath, args, {
    encoding: "utf8", timeout: 60000,
  });
  if (result.error) throw result.error;
  return { status: result.status, data: JSON.parse(result.stdout), stderr: result.stderr };
}

test("published public-key specimen verifies cryptographically with the operator key",
  { skip: !enabled }, () => {
    const good = verifyWith(resolve(SPECIMEN, "cosign.pub"));
    assert.equal(good.status, 0, good.stderr);
    assert.equal(good.data.verdict, "PASS");
    assert.equal(good.data.assertions.find((x) => x.id === "provenance_signature")?.verdict, "PASS");
  });

test("real Cosign refuses a mismatching trust root",
  { skip: !enabled }, () => {
    const bad = verifyWith("/dev/null");
    assert.equal(bad.status, 1, bad.stderr);
    assert.equal(bad.data.verdict, "FAIL");
  });
