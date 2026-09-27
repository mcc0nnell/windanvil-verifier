# Security

WindAnvil Verifier is security-sensitive software. Please report suspected
vulnerabilities privately through GitHub's security reporting features when
available.

The verifier is fail-closed by design: missing required evidence or unavailable
verification capability must produce `BLOCKED`, never `PASS`.

A syntactically valid Assurance Record is not, by itself, proof that an evidence
producer is trustworthy. Consumers must preserve the execution and trust
boundary described in the project documentation.
