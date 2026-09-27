# openCode Source Provenance interoperability specimen

This directory is a frozen WindAnvil verification specimen built from the
public openCode Source Provenance Attestation Service example project.

The evaluated source is commit
`cce3945b8d30e6d1bd55487f34ebff4bdff0536c` from:

https://gitlab.opencode.de/l3montree/source-provenance-attestation-service-example

That project pipeline published the OCI image:

```
registry.opencode.de/l3montree/source-provenance-attestation-service-example
@sha256:06cee1821dcf9ad397f999cf1a4d8b89f2d696da9e52f7b819607fbff1b82664
```

The attached source-provenance statement was verified with Cosign 3.1.3
against the public key published by the openCode attestation service.
## Result

The frozen WindAnvil Assurance Record is **PASS** with six required assertions:

- provenance statement present;
- OCI artifact digest bound by the attestation;
- expected openCode source commit bound by the attestation;
- CycloneDX SBOM present;
- CycloneDX SBOM bound to the same OCI digest; and
- source-provenance signature independently verified with Cosign.

The record digest is:

```
sha256:9e25145b4e60567316c767312dab701b15f97a1a5eb88af895abc72c67441630
```

This is a WindAnvil result, not an openCode or ZenDiS certification or endorsement.
## Evidence

- `verified-attestation.json` — output from successful Cosign verification.
- `cosign.pub` — public verification key retrieved from the attestation service.
- `sbom.cdx.json` — CycloneDX SBOM independently generated with Syft 1.52.0
  from the immutable OCI image.
- `bundle.json` — WindAnvil verifier input and verification metadata.
- `result.json` — complete verifier output and assertion results.
- `assurance-record.json` — portable WindAnvil Assurance Record.

The openCode example image did not itself expose an SBOM attachment at the time
of this capture. WindAnvil therefore generated the SBOM independently from the
immutable image and required that the SBOM identify that exact image digest.
## Reproduction

Two reproduction paths are intentionally separate.

`npm test` checks the frozen specimen offline: record self-digest, provenance
digest, SBOM digest, and verification-metadata digest must all still match.

For a live interoperability replay, install Docker, Cosign, Syft, Node.js, and
jq, then run:

```sh
./specimens/opencode-source-provenance/replay.sh
```

The live replay re-pulls the published tag, refuses to continue if it no longer
resolves to the captured OCI digest, regenerates a CycloneDX SBOM, re-verifies
the registry attestation, and requires a fresh WindAnvil PASS.

A live replay may produce a different Assurance Record digest because the fresh
SBOM and observation timestamp are new evidence. The frozen record remains the
content-bound record of the original verification run.
