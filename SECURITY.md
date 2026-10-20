# Security policy

pyxdw parses untrusted binary files. Malformed input should raise an `XdwError`
subclass; a crash, hang or excessive memory use is a bug worth reporting.

Decompression is bounded by `XdwLimits`; input that would exceed a limit raises
`XdwLimitError` (an `XdwFormatError`). See [limitations](docs/limitations.md).

Please report vulnerabilities privately through GitHub's
"Report a vulnerability" (security advisories) of this repository rather than a
public issue, and do not include confidential documents.

pyxdw does not decrypt protected documents and does not verify signatures.
