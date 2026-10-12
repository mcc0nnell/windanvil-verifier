# Security

WindAnvil Verifier is security-sensitive software. Please report suspected
vulnerabilities privately through GitHub's security reporting features when
available.

The verifier CLI is fail-closed by design: missing trusted signer configuration
or unavailable verification capability must produce `BLOCKED`, never `PASS`.
The CLI's signing key or OIDC signer identity and issuer must come from
operator-controlled flags, **never from the evidence bundle**. Bundled
signature-result booleans and abbreviated assertion lists cannot authorize
`PASS`. The lower-level library evaluates caller-supplied observations,
and requires an independently trusted caller. The operator must also validate
the expected source policy independently.

A syntactically valid Assurance Record is not, by itself, proof that an evidence
producer is trustworthy. Consumers must preserve the execution and trust
boundary described in the project documentation.
