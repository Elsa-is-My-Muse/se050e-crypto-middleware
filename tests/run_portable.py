"""Check portable core contracts without RT-Thread or target hardware.

Requires GCC/G++ or Clang/Clang++, CMake and a native make program. Optional --mbedtls-root
also compiles the actual adapter against the explicitly selected TLS headers.
No serial, flash, provisioning or charging access is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, **kwargs)
    if result.returncode:
        print(result.stdout, result.stderr)
        raise RuntimeError("Command failed: " + " ".join(str(x) for x in command))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mbedtls-root", type=Path, help="matching extern_mbedtls directory")
    args = parser.parse_args()
    cc = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
    cxx = os.environ.get("CXX") or shutil.which("g++") or shutil.which("clang++")
    cmake = shutil.which("cmake")
    make = shutil.which("ninja") or shutil.which("mingw32-make") or shutil.which("make")
    if not all((cc, cxx, cmake, make)):
        parser.error("Need C/C++ compilers, CMake and ninja/mingw32-make/make")
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    for key in ("core_sources", "middleware_sources", "reference_platform_sources"):
        assert all((ROOT / path).is_file() for path in manifest[key]), key
    actual = {p.relative_to(ROOT).as_posix() for folder in ("src", "nxp") for p in (ROOT / folder).glob("*.c")}
    assert actual == set(manifest["core_sources"]), "Core manifest drift"
    for folder in ("src", "middleware"):
        for source in (ROOT / folder).rglob("*.c"):
            text = source.read_text(encoding="utf-8")
            assert not re.search(r"#include\s*[<\"](?:rtthread|at32|se050_sswl|pnc_)", text), source
    includes = [ROOT / path for path in manifest["core_include_dirs"]] + [ROOT / "tests/portable"]
    flags = ["-std=c99", "-Wall", "-Wextra", "-Werror", '-DSE050_PORT_HEADER="se050_port_test.h"']
    flags += ["-D" + value for value in manifest["compile_definitions"]]
    flags += ["-I" + str(path) for path in includes]
    with tempfile.TemporaryDirectory(prefix="se050-portable-") as temporary:
        temp = Path(temporary)
        for name in ("session", "crypto", "poll"):
            exe = temp / (name + ".exe")
            run([cc] + flags + [ROOT / "tests" / ("test_" + name + ".c"), "-o", exe])
            print(run([exe]).stdout.strip())
        # Real C->C++ linkage, not just parsing of extern-C declarations.
        (temp / "api.c").write_text('#include "se050_core.h"\nse050_status_t se050_init(void) { return SE050_OK; }\n')
        (temp / "api.cpp").write_text('#include "se050_core.h"\n#include "se050_port_i2c.h"\nint main() { return se050_init(); }\n')
        run([cc] + flags + ["-c", temp / "api.c", "-o", temp / "api.o"])
        cxxflags = [value for value in flags if value != "-std=c99"]
        run([cxx, "-std=c++11"] + cxxflags + [temp / "api.cpp", temp / "api.o", "-o", temp / "api.exe"])
        run([temp / "api.exe"])
        # Unconfigured template must stop compilation, never silently no-op locks.
        (temp / "template.c").write_text('#include "se050_port_custom.h"\n')
        result = subprocess.run([cc, "-c", "-I" + str(ROOT / "port/template"), str(temp / "template.c"), "-o", str(temp / "template.o")], capture_output=True, text=True)
        assert result.returncode, "Unconfigured OS template unexpectedly compiled"
        (temp / "fake_os.h").write_text('typedef struct { int held; } fake_mutex_t;\n')
        run([cc, "-c", "-I" + str(ROOT / "port/template"), "-I" + str(temp),
             '-DSE050_CUSTOM_PLATFORM_HEADER="fake_os.h"', '-DSE050_CUSTOM_MUTEX_TYPE=fake_mutex_t',
             '-DSE050_CUSTOM_TICKS_PER_SECOND=1000', temp / "template.c", "-o", temp / "template.o"])
        board = temp / "board_mock.c"
        board.write_text(r"""
#include "se050_port_i2c.h"
#include "i2c_a7.h"
#include "sm_timer.h"
#include "nxLog.h"
#include <assert.h>
static uint32_t ticks;
static int owner;
int se050_port_mutex_init(se050_mutex_t *m, const char *n, int f) {(void)n;(void)f;m->held=0;return 0;}
int se050_port_mutex_take(se050_mutex_t *m, int t) {(void)t;assert(!m->held);m->held=1;return 0;}
int se050_port_mutex_release(se050_mutex_t *m) {assert(m->held);m->held=0;return 0;}
void se050_port_critical_enter(void) {}
void se050_port_critical_exit(void) {}
void *se050_port_thread_self(void) {return &owner;}
se050_tick_t se050_port_tick_get(void) {return ++ticks;}
void se050_port_printf(const char *f, ...) {(void)f;}
se050_status_t se050_i2c_init(void) {return -SE050_EIO;}
se050_status_t se050_i2c_probe(void) {return -SE050_EIO;}
se050_status_t se050_i2c_recover(void) {return -SE050_EIO;}
se050_status_t se050_i2c_set_speed(unsigned int k) {(void)k;return -SE050_EIO;}
unsigned int se050_i2c_get_speed(void) {return 100;}
i2c_error_t axI2CInit(void **c,const char *n) {(void)c;(void)n;return I2C_FAILED;}
void axI2CTerm(void *c,int m) {(void)c;(void)m;}
i2c_error_t axI2CWrite(void *c,unsigned char b,unsigned char a,unsigned char *d,unsigned short n) {(void)c;(void)b;(void)a;(void)d;(void)n;return I2C_FAILED;}
i2c_error_t axI2CRead(void *c,unsigned char b,unsigned char a,unsigned char *d,unsigned short n) {(void)c;(void)b;(void)a;(void)d;(void)n;return I2C_FAILED;}
uint32_t sm_initSleep(void) {return 0;}
void sm_sleep(uint32_t ms) {ticks+=ms;}
void sm_usleep(uint32_t us) {(void)us;}
uint8_t nLog_Init(void) {return 0;}
void nLog_DeInit(void) {}
void nLog(const char *c,int l,const char *f,...) {(void)c;(void)l;(void)f;}
void nLog_au8(const char *c,int l,const char *m,const unsigned char *a,size_t n) {(void)c;(void)l;(void)m;(void)a;(void)n;}
""", encoding="utf-8")
        (temp / "main.c").write_text(r"""
#include "se050_core.h"
#include <assert.h>
int main(void) {
    int exists=1;
    assert(se050_init()!=SE050_OK);
    assert(se050_key_exists(SE050_TLS_ISO2_OBJECT,&exists)!=SE050_OK);
    return 0;
}
""", encoding="utf-8")
        generator = "Ninja" if Path(make).stem == "ninja" else "MinGW Makefiles" if os.name == "nt" else "Unix Makefiles"
        common = [cmake, "-G", generator, "-DCMAKE_C_COMPILER=" + str(cc), "-DCMAKE_MAKE_PROGRAM=" + str(make)]
        # An unspecified production port must also fail CMake configuration.
        bad = subprocess.run(common + ["-S", str(ROOT), "-B", str(temp / "bad")], capture_output=True, text=True)
        assert bad.returncode and "Select a real OS header" in bad.stderr
        project = temp / "project"
        project.mkdir()
        (project / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.19)\nproject(portable_smoke C)\n'
            + 'add_subdirectory("' + ROOT.as_posix() + '" se050)\n'
            + 'add_executable(portable_smoke "' + (temp / "main.c").as_posix() + '")\n'
            + 'target_link_libraries(portable_smoke PRIVATE SE050::Core)\n', encoding="utf-8")
        options = ['-DSE050_OS_PORT_HEADER=se050_port_test.h', '-DSE050_PORT_INCLUDE_DIRS=' + (ROOT / "tests/portable").as_posix(), '-DSE050_PLATFORM_SOURCES=' + board.as_posix()]
        if args.mbedtls_root:
            tls = args.mbedtls_root.resolve()
            crypto = tls / "tf-psa-crypto"
            inc = [ROOT / "tests", tls / "include", crypto / "include", crypto / "core", crypto / "drivers/builtin/include"]
            options += ['-DSE050_WITH_MBEDTLS=ON', '-DSE050_MBEDTLS_INCLUDE_DIRS=' + ';'.join(p.as_posix() for p in inc),
                        '-DSE050_MBEDTLS_COMPILE_DEFINITIONS=__forceinline=__inline__;TF_PSA_CRYPTO_CONFIG_FILE="host_crypto_config.h";MBEDTLS_CONFIG_FILE="host_crypto_config.h"']
            (temp / "tls_headers.cpp").write_text('#include "se050_library.h"\nint main() { return 0; }\n')
            run([cxx, '-std=c++11', '-fsyntax-only', '-D__forceinline=__inline__',
                 '-DTF_PSA_CRYPTO_CONFIG_FILE="host_crypto_config.h"', '-DMBEDTLS_CONFIG_FILE="host_crypto_config.h"']
                + cxxflags + ['-I' + str(p) for p in inc] + [temp / "tls_headers.cpp"])
        run(common + options + ["-S", project, "-B", temp / "build"])
        run([cmake, "--build", temp / "build", "--parallel", "4"])
        exe = temp / "build" / ("portable_smoke.exe" if os.name == "nt" else "portable_smoke")
        run([exe])
    print("Portable tests PASS: custom OS, core/CMake link, C++ API, template guards; no RT-Thread dependency.")
    if args.mbedtls_root:
        print("Selected Mbed TLS adapter CMake compile and C++ headers PASS (hardware/TLS runtime not exercised).")


if __name__ == "__main__":
    main()
