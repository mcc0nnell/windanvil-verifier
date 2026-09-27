# WindAnvil Verifier

Independent, fail-closed verification of software supply-chain claims.

WindAnvil Verifier consumes an artifact identity, SLSA/in-toto provenance,
CycloneDX or SPDX SBOM evidence, and an independent provenance-signature result.
It checks whether the evidence actually binds the claimed artifact and source,
then emits a portable WindAnvil Assurance Record.

**Attestation proves who made a claim. WindAnvil preserves independent evidence
about whether the claim survived verification.**

This project is Apache-2.0 and intentionally separate from the private WindAnvil
assurance lab.

## Why this exists

Modern supply-chain systems can already create and sign SBOMs and provenance.
The remaining assurance problem is different: a signed statement can be validly
signed while still failing to establish the source/artifact relationship that a
consumer expected.

WindAnvil Verifier keeps those questions separate:

1. Was provenance present?
2. Does it name the artifact digest being evaluated?
3. Does it bind the expected immutable source material?
4. Is a recognized CycloneDX or SPDX SBOM present?
5. Does that SBOM bind the same artifact digest?
6. Was the provenance signature independently verified?

The default policy requires all six. A proven mismatch returns `FAIL`.
Missing evidence or unavailable verification capability returns `BLOCKED`.
Only a complete set of required proofs returns `PASS`.

## openCode / DevGuard seam

openCode and DevGuard already use in-toto, SLSA, Cosign, CycloneDX and related
attestations. WindAnvil Verifier is designed as an independent evidence layer
beside those systems, not a replacement for them.

The intended flow is:

```
source -> build -> artifact
             |
             +-> SLSA provenance / SBOM / Cosign
                              |
                              v
                    WindAnvil Verifier
                              |
                              v
                  WindAnvil Assurance Record
```

The first implementation supports SLSA provenance v1/v0.2 material binding,
the openCode Source Provenance Attestation Service commit-binding model,
CycloneDX/SPDX recognition, and both keyless and public-key Cosign verification.

The openCode path is tested against the service's public schema and documented
verification boundary. This project is not affiliated with ZenDiS, openCode, or
DevGuard.

### Real openCode specimen

[`specimens/opencode-source-provenance/`](specimens/opencode-source-provenance/)
contains a public end-to-end specimen using openCode's own example project and
registry artifact. The source-provenance signature verifies against the
service's published public key; an independently generated CycloneDX SBOM binds
the same immutable OCI digest; the resulting WindAnvil Assurance Record is
`PASS`.

The specimen includes both frozen evidence-integrity tests and a live replay
script.

## Install

Node.js 20 or later is required.

```sh
npm install
npm test
```

The current package pins
[`windanvil-assurance-record`](https://github.com/mcc0nnell/windanvil-assurance-record)
to a specific Git commit so the evidence model used by a verifier build is
reproducible.

For signed OCI provenance, install `cosign`. The verifier supports either a
keyless certificate identity/issuer pair or a public key plus predicate type.
The latter matches openCode's Source Provenance Attestation Service boundary.

## CLI

```sh
windanvil-verifier verify evidence-bundle.json
```

Exit codes:

- `0`: PASS
- `1`: FAIL
- `2`: BLOCKED
- `64`: CLI usage error
- `70`: verifier/input error
A minimal bundle looks like:

```json
{
  "artifact": {
    "kind": "oci_artifact",
    "name": "registry.example/app",
    "digest": "sha256:<artifact digest>"
  },
  "expectedSource": {
    "uri": "git+https://example.org/project",
    "digest": "sha256:<source digest>"
  },
  "sboms": [
    { "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [] }
  ],
  "cosign": {
    "reference": "registry.example/app@sha256:<artifact digest>",
    "certificateIdentity": "<expected workload identity>",
    "certificateIssuer": "<expected OIDC issuer>"
  }
}
```

For openCode's keyed Source Provenance Attestation Service, start from
[`examples/opencode-bundle.example.json`](examples/opencode-bundle.example.json)
and use the operator-published `cosign.pub`. Keep the predicate type explicit
because the service schema is versioned.

When `cosign` verification succeeds, the verifier evaluates the provenance
statement returned by that verification command. It does not substitute an
unverified local provenance document for the signed statement.
## Assurance semantics

The verifier uses the public
[`windanvil-assurance-record`](https://github.com/mcc0nnell/windanvil-assurance-record)
package for deterministic evidence digests and terminal PASS / FAIL / BLOCKED
semantics.

The Assurance Record binds:

- immutable artifact digest;
- expected source identity;
- policy digest;
- verification-plan digest;
- observation digests;
- receipt digest; and
- terminal verdict.

A record proves what this verifier observed under a specific policy. It does not
claim that every producer of a syntactically valid record is trustworthy.

## Scope

Version 0.1 deliberately does **not**:

- generate SBOMs;
- build software;
- scan for vulnerabilities;
- replace Cosign, in-toto, SLSA, DevGuard, or openCode;
- infer PASS when a required verifier is unavailable; or
- certify compliance with the Cyber Resilience Act or any other regulation.

Those boundaries are part of the assurance model.
