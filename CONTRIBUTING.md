# Contributing

欢迎提交问题、文档改进和代码变更。讨论可使用中文或 English。

## Before changing code

Read the [README](README.en.md) and [TLS integration notes](integration/mbedtls/README.md).
Keep OS / board dependencies in `port/`, and update `manifest.json` when the source
inventory changes. Preserve existing public APIs and object IDs unless a change
and migration plan are explicitly documented. Preserve vendor notices and record
changes to `nxp/` in `nxp/UPSTREAM.md`.

## Local checks

Use Python 3.9+, CMake 3.19+, GCC/G++ or Clang/Clang++, and Ninja / Make.

```sh
python -m pip install -r requirements-dev.txt
python tools/check_project.py
python tools/format.py --check
python tests/run.py
python tests/run_portable.py
python -m unittest discover -s tests -p "test_tools.py"
```

Owned C/C++ files use clang-format 16, four spaces, Allman braces and a 100-column
limit. `python tools/format.py` applies the format; `nxp/` is excluded.
Use UTF-8 and LF for maintained source and documentation.

If changing PSA / TLS integration, also validate against the exact selected TLS
tree. On Windows with MinGW:

```sh
python tools/check_tls_integration.py /path/to/extern_mbedtls
python tests/run_portable.py --mbedtls-root /path/to/extern_mbedtls
python tests/run_psa.py --mbedtls-root /path/to/extern_mbedtls
```

That external tree is not distributed here. Host mocks do not establish hardware
performance or handshake success. Report board, applet, toolchain and stack
versions when supplying hardware evidence.

## Pull requests and reports

Describe the concrete problem, resulting behavior and relevant checks. Add tests
when they exercise a changed behavior or a real regression. Include error output
and a minimal reproduction, with secrets and customer data removed. Avoid
unrelated formatting changes and automatic provisioning in tests.

Use [private security reporting](SECURITY.md) for vulnerabilities. Do not attach
private keys, provisioning data, flash dumps or full APDU payloads to issues.
Contributions are provided under the repository's [Apache-2.0 license](LICENSE).
