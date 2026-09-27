// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import {
  buildAssuranceRecord,
  digestOf,
  evaluateRequiredAssertions,
  isDigest,
} from "windanvil-assurance-record";

const SHA256_HEX = /^[0-9a-f]{64}$/i;
const SLSA_V1 = "https://slsa.dev/provenance/v1";
const SLSA_V02 = "https://slsa.dev/provenance/v0.2";
const DEFAULT_REQUIRED = Object.freeze([
  "provenance_present",
  "artifact_bound",
  "source_bound",
  "sbom_present",
  "provenance_signature",
]);

export function normalizeSha256(value) {
  if (typeof value !== "string") return null;
  if (isDigest(value)) return value;
  if (SHA256_HEX.test(value)) return `sha256:${value.toLowerCase()}`;
  return null;
}

function decodeBase64Json(payload) {
  if (typeof payload !== "string" || payload.length === 0) return null;
  try {
    return JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

export function unwrapStatement(value) {
  if (!value || typeof value !== "object") return null;
  if (Array.isArray(value)) {
    for (const candidate of value) {
      const statement = unwrapStatement(candidate);
      if (statement) return statement;
    }
    return null;
  }

  if (Array.isArray(value.subject) && value.predicateType) return value;
  if (value.payload) return decodeBase64Json(value.payload);
  if (value.dsseEnvelope?.payload) return decodeBase64Json(value.dsseEnvelope.payload);
  if (value.bundle?.dsseEnvelope?.payload) {
    return decodeBase64Json(value.bundle.dsseEnvelope.payload);
  }
  return null;
}

function slsaPredicate(statement) {
  if (!statement) return null;
  if (statement.predicateType !== SLSA_V1 && statement.predicateType !== SLSA_V02) {
    return null;
  }
  return statement.predicate ?? null;
}
function digestFromMap(map) {
  if (!map || typeof map !== "object") return null;
  return normalizeSha256(map.sha256);
}

export function artifactIsSubject(statement, artifactDigest) {
  const expected = normalizeSha256(artifactDigest);
  if (!expected || !Array.isArray(statement?.subject)) return false;
  return statement.subject.some((subject) => digestFromMap(subject?.digest) === expected);
}

function provenanceMaterials(statement) {
  const predicate = slsaPredicate(statement);
  if (!predicate) return [];
  const v1 = predicate.buildDefinition?.resolvedDependencies;
  if (Array.isArray(v1)) return v1;
  if (Array.isArray(predicate.materials)) return predicate.materials;
  return [];
}

export function sourceIsMaterial(statement, expectedSource) {
  if (!expectedSource || typeof expectedSource.uri !== "string") return false;

  const openCodeCommit = statement?.predicate?.sourceDefinition?.sourceControl?.commit;
  if (openCodeCommit?.uri) {
    if (openCodeCommit.uri !== expectedSource.uri) return false;
    const wantedRevision = expectedSource.revision ?? expectedSource.digest;
    return wantedRevision ? openCodeCommit.hash === wantedRevision : true;
  }

  const wantedDigest = expectedSource.digest
    ? normalizeSha256(expectedSource.digest)
    : null;
  if (expectedSource.digest && !wantedDigest) return false;

  return provenanceMaterials(statement).some((material) => {
    if (material?.uri !== expectedSource.uri) return false;
    if (!wantedDigest) return true;
    return digestFromMap(material?.digest) === wantedDigest;
  });
}
export function detectSbom(value) {
  const statement = unwrapStatement(value);
  const candidate = statement?.predicate ?? value;
  if (!candidate || typeof candidate !== "object") return null;
  if (candidate.bomFormat === "CycloneDX") {
    return { format: "cyclonedx", specVersion: candidate.specVersion ?? null };
  }
  if (typeof candidate.spdxVersion === "string") {
    return { format: "spdx", specVersion: candidate.spdxVersion };
  }
  return null;
}

function assertion(id, verdict, reason) {
  return { id, verdict, reason };
}

function signatureAssertion(verification) {
  const reason = verification?.provenanceSignatureReason;
  if (verification?.provenanceSignature === true) {
    return assertion("provenance_signature", "PASS", reason ?? "provenance signature independently verified");
  }
  if (verification?.provenanceSignature === false) {
    return assertion("provenance_signature", "FAIL", reason ?? "provenance signature verification failed");
  }
  return assertion(
    "provenance_signature",
    "BLOCKED",
    reason ?? "no independent provenance-signature verification result",
  );
}
export function verifySupplyChainBundle(bundle, options = {}) {
  if (!bundle || typeof bundle !== "object") throw new TypeError("bundle must be an object");

  const artifactDigest = normalizeSha256(bundle.artifact?.digest);
  if (!artifactDigest) throw new TypeError("artifact.digest must be a sha256 digest");
  if (!bundle.expectedSource || typeof bundle.expectedSource.uri !== "string") {
    throw new TypeError("expectedSource.uri is required");
  }

  const statement = unwrapStatement(bundle.provenance);
  const sboms = Array.isArray(bundle.sboms) ? bundle.sboms : [];
  const sbomKinds = sboms.map(detectSbom).filter(Boolean);
  const assertions = [
    statement
      ? assertion("provenance_present", "PASS", "SLSA/in-toto statement present")
      : assertion("provenance_present", "BLOCKED", "no readable provenance statement"),
    statement && artifactIsSubject(statement, artifactDigest)
      ? assertion("artifact_bound", "PASS", "artifact digest is a provenance subject")
      : assertion("artifact_bound", statement ? "FAIL" : "BLOCKED", "artifact digest not bound by provenance"),
    statement && sourceIsMaterial(statement, bundle.expectedSource)
      ? assertion("source_bound", "PASS", "expected source is bound by provenance")
      : assertion("source_bound", statement ? "FAIL" : "BLOCKED", "expected source not bound by provenance"),
    sbomKinds.length > 0
      ? assertion("sbom_present", "PASS", `recognized SBOM: ${sbomKinds.map((x) => x.format).join(",")}`)
      : assertion("sbom_present", "BLOCKED", "no recognized CycloneDX or SPDX SBOM"),
    signatureAssertion(bundle.verification),
  ];
  const required = options.requiredAssertions ?? bundle.requiredAssertions ?? DEFAULT_REQUIRED;
  const evaluation = evaluateRequiredAssertions(required, assertions);
  const policyId = options.policyId ?? bundle.policyId ?? "windanvil.opencodesupply.v1";
  const policy = { id: policyId, requiredAssertions: [...required] };
  const plan = {
    kind: "windanvil.verification-plan",
    version: 1,
    artifactDigest,
    expectedSource: bundle.expectedSource,
    requiredAssertions: [...required],
  };
  const observationDigests = assertions.map((item) => digestOf(item)).sort();
  const subject = {
    kind: bundle.artifact?.kind ?? "oci_artifact",
    identity: {
      digest: artifactDigest,
      ...(bundle.artifact?.name ? { name: bundle.artifact.name } : {}),
    },
  };
  const receiptId = digestOf({
    subject,
    policyDigest: digestOf(policy),
    planDigest: digestOf(plan),
    observationDigests,
  });
  const receiptBody = {
    id: receiptId,
    verdict: evaluation.verdict,
    reason: evaluation.reason,
    observationDigests,
  };

  const record = buildAssuranceRecord({
    generatedAt: options.generatedAt ?? bundle.generatedAt,
    subject,
    policy: { id: policyId, digest: digestOf(policy) },
    plan: { digest: digestOf(plan) },
    receipt: { id: receiptId, digest: digestOf(receiptBody) },
    verdict: { value: evaluation.verdict, reason: evaluation.reason },
    evidence: {
      observationDigests,
      artifactDigests: [artifactDigest],
    },
  });

  return {
    verdict: evaluation.verdict,
    reason: evaluation.reason,
    assertions,
    sboms: sbomKinds,
    record,
  };
}

function parseCosignOutput(stdout) {
  const text = String(stdout ?? "").trim();
  if (!text) return null;
  try {
    return unwrapStatement(JSON.parse(text));
  } catch {
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const statement = unwrapStatement(JSON.parse(line));
        if (statement) return statement;
      } catch {
        // Continue: cosign may mix informational output with JSON.
      }
    }
  }
  return null;
}
export function verifyCosignAttestation({
  reference,
  predicateType = "slsaprovenance",
  publicKey,
  certificateIdentity,
  certificateIssuer,
  ignoreTransparencyLog = false,
  cosign = "cosign",
  runner = execFileSync,
}) {
  if (!reference) throw new TypeError("reference is required");

  const args = ["verify-attestation"];
  if (publicKey) {
    args.push("--key", publicKey);
    if (ignoreTransparencyLog) args.push("--insecure-ignore-tlog");
  } else if (certificateIdentity && certificateIssuer) {
    args.push(
      "--certificate-identity", certificateIdentity,
      "--certificate-oidc-issuer", certificateIssuer,
    );
  } else {
    return {
      verified: null,
      statement: null,
      reason: "public key or certificate identity/issuer is required",
    };
  }

  args.push("--type", predicateType, "--output", "json", reference);

  try {
    const stdout = runner(cosign, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const statement = parseCosignOutput(stdout);
    if (!statement) {
      return { verified: null, statement: null, reason: "cosign succeeded but no statement could be decoded" };
    }
    return { verified: true, statement, reason: "cosign verified provenance attestation" };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        verified: null,
        statement: null,
        reason: `cosign unavailable: ${cosign} was not found`,
      };
    }
    return {
      verified: false,
      statement: null,
      reason: `cosign verification failed: ${error?.message ?? "unknown error"}`,
    };
  }
}

export const verifyCosignProvenance = verifyCosignAttestation;

export const DEFAULT_REQUIRED_ASSERTIONS = DEFAULT_REQUIRED;
