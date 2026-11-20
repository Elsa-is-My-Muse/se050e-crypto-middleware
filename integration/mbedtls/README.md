# Version-pinned stack hooks

This directory packages the existing four low-level SE050 hooks from the current
repository, not a generic Mbed TLS driver for all releases. `manifest.json`
records the base commit and LF-normalized SHA256 of base/patched files.
`se050-stack.patch` is relative to the `extern_mbedtls` root.

Read the [project integration overview](../../README.en.md#integrating-a-platform) before use.
The read-only checker is [check_tls_integration.py](../../tools/check_tls_integration.py). Apply only to the exact base after a
successful check. Never force a patch onto a different stack or reapply to an
already-patched one. Application entropy, identity/handle lifecycle, handshake
scope, certificates and policy remain explicit host responsibilities.

Upstream source licenses remain with the selected Mbed TLS/TF-PSA tree. This
integration patch does not replace their source or license files.
