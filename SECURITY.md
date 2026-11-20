# Security policy

## Reporting a vulnerability

Use this repository's **Security → Advisories → Report a vulnerability** option
for a private report. If that option is unavailable, open an issue requesting a
private contact method without including vulnerability details.

Provide the affected commit, configuration, reproduction steps, impact and any
proposed fix. Remove private keys, credentials, provisioning material, customer
identities, flash dumps and APDU payloads. Do not disclose exploit details in a
public issue before coordinated review.

This project is maintained on a best-effort basis. There is no guaranteed response
SLA or maintenance window; fixes target the current `main` branch.

## Integration boundaries

The host application owns trusted time, certificate and peer validation, identity
selection, secure provisioning, connection cleanup and policy. The bundled
transport does not implement SCP03. A successful host build or mock test is not
proof of hardware security or ISO 15118 conformance.

When hardware entropy or identity signing is required by the application,
chip failures must fail closed. Do not silently substitute weak entropy or a
software identity. Review the [TLS integration notes](integration/mbedtls/README.md) before use.
