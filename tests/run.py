"""Run mocked session tests; no target board or key provisioning required."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

tests = Path(__file__).resolve().parent
port = tests.parent
compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
if not compiler:
    raise SystemExit("Set CC to a host GCC or Clang compiler")
with tempfile.TemporaryDirectory(prefix="se050-tests-") as temp:
    for name in ("session", "crypto", "poll"):
        exe = Path(temp) / (name + ".exe")
        subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                        "-DSSS_USE_FTR_FILE", "-DT1oI2C", "-DT1oI2C_UM11225",
                        "-DAX_EMBEDDED=1", "-DUSE_RTOS=0", "-I" + str(tests), "-I" + str(port / "include"), "-I" + str(port / "src"),
                        "-I" + str(port / "port/rtthread"), "-I" + str(port / "port/nxp"),
                        "-I" + str(port / "nxp"), str(tests / ("test_" + name + ".c")),
                        "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
