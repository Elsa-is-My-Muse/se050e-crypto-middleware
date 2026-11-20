"""Test real PSA/PK/CSR with a mocked SE050, using an explicit matching TLS tree.

Requires Windows, MinGW GCC and the external version-pinned Mbed TLS / TF-PSA
sources. No board access or key provisioning is performed.
"""
import argparse
import concurrent.futures
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mbedtls-root", type=Path, required=True, help="matching patched extern_mbedtls tree")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args()
    compiler = os.environ.get("CC") or shutil.which("gcc")
    if os.name != "nt" or not compiler:
        parser.error("This test runner requires Windows and MinGW GCC")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    stack = args.mbedtls_root.resolve()
    crypto = stack / "tf-psa-crypto"
    if not (crypto / "core/psa_crypto.c").is_file():
        parser.error("--mbedtls-root must contain tf-psa-crypto/core/psa_crypto.c")
    subprocess.run([sys.executable, str(ROOT / "tools/check_tls_integration.py"), str(stack)], check=True)
    tests = ROOT / "tests"
    includes = [tests, ROOT / "include", ROOT / "port/rtthread", stack / "include", crypto / "include",
                crypto / "core", crypto / "drivers/builtin/include", crypto / "drivers/builtin/src"]
    flags = ["-std=c99", "-O1", "-D__forceinline=__inline__", "-ffunction-sections", "-fdata-sections",
             '-DTF_PSA_CRYPTO_CONFIG_FILE="host_crypto_config.h"',
             '-DMBEDTLS_CONFIG_FILE="host_crypto_config.h"']
    flags += ["-I" + str(p) for p in includes]
    sources = sorted((crypto / "core").glob("*.c"))
    sources += sorted((crypto / "drivers/builtin/src").glob("*.c"))
    sources += [crypto / "drivers/p256-m/p256-m/p256-m.c"]
    sources += [stack / "library" / name for name in
                ("x509.c", "x509_create.c", "x509_csr.c", "x509write_csr.c", "x509_oid.c", "x509write.c")]
    sources += [ROOT / "middleware/mbedtls/se050_psa.c", tests / "test_psa.c"]
    with tempfile.TemporaryDirectory(prefix="se050-psa-") as temporary:
        temp = Path(temporary)

        def compile_one(item):
            index, source = item
            output = temp / (str(index) + ".o")
            result = subprocess.run([compiler] + flags + ["-c", str(source), "-o", str(output)],
                                    capture_output=True, text=True)
            return result, output, source

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(compile_one, enumerate(sources)))
        failures = [(r, s) for r, _, s in results if r.returncode]
        for result, source in failures:
            print(source, result.stdout, result.stderr)
        if failures:
            raise SystemExit(str(len(failures)) + " native compilation(s) failed")
        exe = temp / "psa.exe"
        result = subprocess.run([compiler] + [str(o) for _, o, _ in results] +
                                ["-Wl,--gc-sections", "-ladvapi32", "-o", str(exe)],
                                capture_output=True, text=True)
        if result.returncode:
            print(result.stdout, result.stderr)
            raise SystemExit("Native link failed")
        subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    main()
