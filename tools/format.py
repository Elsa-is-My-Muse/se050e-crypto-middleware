"""Format/check owned C/C++ code only; never rewrite nxp/ vendor files."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OWNED = ("include", "src", "middleware", "port", "adapters", "tests")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="read-only formatting validation")
    args = parser.parse_args()
    tool = os.environ.get("CLANG_FORMAT") or shutil.which("clang-format")
    if not tool:
        parser.error("Set CLANG_FORMAT or install clang-format (baseline: version 16)")
    files = sorted(p for folder in OWNED for p in (ROOT / folder).rglob("*")
                   if p.is_file() and p.suffix in (".c", ".h", ".cpp", ".hpp"))
    if not files:
        parser.error("No owned source files found")
    flags = ["--dry-run", "--Werror"] if args.check else ["-i"]
    subprocess.run([tool, "--style=file"] + flags + [str(p) for p in files], check=True)
    print(f"SE050 format {'check' if args.check else 'update'}: {len(files)} files; vendor nxp/ excluded")


if __name__ == "__main__":
    main()
