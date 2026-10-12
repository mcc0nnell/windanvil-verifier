#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// CLI trust boundary: bundle metadata is evidence, never authority.
import { readFile } from "node:fs/promises";
import {
  DEFAULT_REQUIRED_ASSERTIONS,
  normalizeSha256,
  verifyCosignProvenance,
  verifySupplyChainBundle,
} from "./index.js";

function usage() {
  console.error(
    "usage: windanvil-verifier verify <bundle.json> [--trusted-public-key <path> " +
    "| --trusted-certificate-identity <identity> --trusted-certificate-issuer <issuer>] " +
    "[--predicate-type <type>] [--ignore-transparency-log]\n" +
    "Keys and certificate identities must be supplied independently of the evidence bundle. " +
    "Without explicit trust configuration, the result is BLOCKED.",
  );
}

function parseArgs(argv) {
  const [command, file, ...rest] = argv;
  if (command !== "verify" || !file || file.startsWith("--")) return null;
  const options = {};
  const valueOptions = new Map([
    ["--trusted-public-key", "publicKey"],
    ["--trusted-certificate-identity", "certificateIdentity"],
    ["--trusted-certificate-issuer", "certificateIssuer"],
    ["--predicate-type", "predicateType"],
  ]);
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === "--ignore-transparency-log") {
      if (options.ignoreTransparencyLog !== undefined) return null;
      options.ignoreTransparencyLog = true;
    } else if (valueOptions.has(arg)) {
      const key = valueOptions.get(arg);
      if (options[key] !== undefined || !rest[i + 1] || rest[i + 1].startsWith("--")) return null;
      options[key] = rest[++i];
    } else {
      return null;
    }
  }
  if (options.publicKey && (options.certificateIdentity || options.certificateIssuer)) return null;
  if (Boolean(options.certificateIdentity) !== Boolean(options.certificateIssuer)) return null;
  if (options.ignoreTransparencyLog && !options.publicKey) return null;
  return { file, options };
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed) {
    usage();
    process.exitCode = 64;
    return;
  }
  const { file, options } = parsed;
  const input = JSON.parse(await readFile(file, "utf8"));

  // These fields arrive in an untrusted evidence document: never accept them
  // as signature proof or as permission to reduce the required policy.
  const artifactDigest = normalizeSha256(input.artifact?.digest);
  const artifactName = input.artifact?.name;
  const reference = input.cosign?.reference;
  const expectedReference = artifactName && artifactDigest
    ? `${artifactName}@${artifactDigest}`
    : null;
  const hasTrustedKey = Boolean(options.publicKey);
  const hasTrustedIdentity = Boolean(options.certificateIdentity && options.certificateIssuer);
  let verified = {
    verified: null,
    statement: null,
    reason: "operator-trusted public key or certificate identity/issuer is required",
  };

  if (hasTrustedKey || hasTrustedIdentity) {
    if (!reference || !expectedReference || reference !== expectedReference ||
        !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$/.test(reference)) {
      verified.reason = "cosign reference must match the named artifact and its sha256 digest";
    } else {
      // None of the bundle's cosign options (including executable path,
      // public key, identity, predicate type, or tlog bypass) are authoritative.
      verified = verifyCosignProvenance({
        reference,
        publicKey: options.publicKey,
        certificateIdentity: options.certificateIdentity,
        certificateIssuer: options.certificateIssuer,
        predicateType: options.predicateType ?? "slsaprovenance",
        ignoreTransparencyLog: options.ignoreTransparencyLog === true,
      });
    }
  }

  const trustedInput = {
    ...input,
    // Even if a caller asserts PASS in the bundle, only Cosign's result
    // performed under separately supplied trust settings can satisfy it.
    verification: {
      provenanceSignature: verified.verified,
      provenanceSignatureReason: verified.reason,
    },
    // Never use a potentially unverified statement if verification was invoked.
    provenance: verified.statement ?? (hasTrustedKey || hasTrustedIdentity ? null : input.provenance),
  };
  const result = verifySupplyChainBundle(trustedInput, {
    requiredAssertions: DEFAULT_REQUIRED_ASSERTIONS,
    policyId: "windanvil.cli.trusted-cosign.v1",
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.verdict === "FAIL") process.exitCode = 1;
  if (result.verdict === "BLOCKED") process.exitCode = 2;
}

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exitCode = 70;
});
