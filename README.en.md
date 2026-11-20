# SE050E Crypto Middleware

[![CI](https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-99-blue.svg)](CMakeLists.txt)

**Portable C cryptographic middleware for the NXP SE050E secure element.**

[中文](README.md) | English

The library provides serialized chip sessions, key-object management, random bytes,
ECDSA and optional ECDH, plus PSA / Mbed TLS integration for existing ISO 15118-2
and ISO 15118-20 applications. The core is independent of TLS. Applications supply
the MCU, OS and I2C implementation. This independent project does not include a
complete ISO 15118 protocol stack or an official NXP SDK.

## Features and scope

| Component | Functionality | Requirements |
| --- | --- | --- |
| Core | Sessions, APDUs, random bytes, key-object lifecycle | OS and board port |
| ECC | P-256 / P-384 / P-521, ECDSA, DER/raw conversion, ECDH | Matching chip applet capabilities |
| PSA / TLS | Opaque keys, identity signing, CSR, optional verification and key exchange | Matching Mbed TLS 4.0.0 / TF-PSA-Crypto tree |
| Reference port | AT32F435 + RT-Thread, 100 kHz default I2C | External BSP / HAL / RTOS |
| Host validation | Sessions, APDUs, cleanup, polling, CMake linking, C++ API | Python, C/C++ compilers, CMake |

TLS hooks are tied to the [recorded base and file hashes](integration/mbedtls/manifest.json).
Compatibility with other stack versions is not assumed. The host owns entropy
integration, certificates, time policy, secure provisioning and handshake policy.

## Quick start

Use Python 3.9+, CMake 3.19+, GCC/G++ or Clang/Clang++, and Ninja or Make.
On Windows, use MinGW-w64 and Ninja. Set `CC` / `CXX` to select compilers.

```sh
git clone https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware.git
cd se050e-crypto-middleware
python -m pip install -r requirements-dev.txt
python tools/check_project.py
python tools/format.py --check
python tests/run.py
python tests/run_portable.py
python -m unittest discover -s tests -p "test_tools.py"
```

These checks use host mocks. They do not access boards, provision keys or flash firmware.

## Integrating a platform

Implement the [OS port contract](port/template/se050_port_custom.h) and
[board transport contract](include/se050_port_i2c.h), then select them in the parent CMake project:

```cmake
set(SE050_OS_PORT_HEADER "my_se050_port.h" CACHE STRING "")
set(SE050_PORT_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/platform" CACHE STRING "")
set(SE050_PLATFORM_SOURCES
    "${PROJECT_SOURCE_DIR}/platform/my_se050_os.c;${PROJECT_SOURCE_DIR}/platform/my_se050_i2c.c;${PROJECT_SOURCE_DIR}/platform/my_se050_time_log.c"
    CACHE STRING "")
add_subdirectory(third_party/se050e-crypto-middleware)
target_link_libraries(my_application PRIVATE SE050::Core)
```

Include `se050_core.h` for the TLS-independent API. To use the optional adapter,
follow the [TLS integration notes](integration/mbedtls/README.md), enable
`SE050_WITH_MBEDTLS`, configure matching headers, definitions and libraries,
and link `SE050::MbedTLS`. CMake rejects incomplete platform selections.

## Exporting source

```sh
python tools/export_portable.py ../se050e-source
python tools/export_portable.py ../se050e-source-with-tests --with-tests
```

The destination must be outside the source tree and new or empty. The exporter
copies an allowlist of source and documentation files, verifies each SHA256,
and writes `PACKAGE_MANIFEST.json`. It excludes private keys, test PKI,
firmware, flash backups and build outputs.

## Repository layout

```text
include/              Public core and PSA / TLS API
src/                  Platform-independent sessions, APDUs and ECC
middleware/mbedtls/    PSA / Mbed TLS adapter
port/                 AT32F435 / RT-Thread reference port and OS template
nxp/                  Attributed NXP transport subset
integration/mbedtls/   Version-specific TLS hooks and hashes
manifest.json         Source, include-path and definition inventory
tests/                Host mocks, portable build checks and tool tests
tools/                Formatting, integrity checks and source export
.github/              CI and contribution templates
```

## Validation and maintenance

- [TLS integration notes](integration/mbedtls/README.md): version baseline and host responsibilities.
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).

Host tests do not prove real TLS handshakes or new-board readiness. Validate
bus timing, concurrency, recovery, certificate policy and both endpoints on the
actual hardware. The bundled plain-T1 transport does not provide SCP03.

## License

[Apache License 2.0](LICENSE). Vendor files retain their NXP copyright and
license notices; see [upstream provenance](nxp/UPSTREAM.md) and [NOTICE](NOTICE).
Mbed TLS / TF-PSA-Crypto are supplied separately under their own licenses.
