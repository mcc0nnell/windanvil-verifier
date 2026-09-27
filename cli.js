#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { readFile } from "node:fs/promises";
import {
  verifyCosignProvenance,
  verifySupplyChainBundle,
} from "./index.js";

function usage() {
  console.error(
    "usage: windanvil-verifier verify <bundle.json>\n" +
    "bundle.cosign may specify reference, certificateIdentity, and certificateIssuer",
  );
}

async function main() {
  const [command, file] = process.argv.slice(2);
  if (command !== "verify" || !file) {
    usage();
    process.exitCode = 64;
    return;
  }

  const bundle = JSON.parse(await readFile(file, "utf8"));
  if (bundle.cosign?.reference) {
    const result = verifyCosignProvenance(bundle.cosign);
    bundle.verification = {
      ...(bundle.verification ?? {}),
      provenanceSignature: result.verified,
      provenanceSignatureReason: result.reason,
    };
    if (result.statement) bundle.provenance = result.statement;
  }

  const result = verifySupplyChainBundle(bundle);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (result.verdict === "FAIL") process.exitCode = 1;
  if (result.verdict === "BLOCKED") process.exitCode = 2;
}

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exitCode = 70;
});
