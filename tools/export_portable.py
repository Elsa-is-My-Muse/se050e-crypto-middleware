"""Export an allowlisted SE050E source package, with hashes and no build/PKI files."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ("include", "src", "middleware", "port", "nxp", "integration", "tools")
TOP_FILES = ("README.md", "README.en.md", "LICENSE", "NOTICE", "CONTRIBUTING.md", "SECURITY.md",
             "CMakeLists.txt", "manifest.json", "requirements-dev.txt", ".clang-format",
             ".editorconfig", ".gitattributes", ".gitignore")
SUFFIXES = {".c", ".h", ".cpp", ".hpp", ".py", ".md", ".json", ".patch", ".txt"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new empty directory, outside the source tree")
    parser.add_argument("--with-tests", action="store_true", help="include host mocks, without hardware PKI fixtures")
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        parser.error("Destination must be outside the source tree")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        parser.error("Destination must be new or empty; no existing files will be overwritten")
    folders = list(DIRECTORIES)
    if args.with_tests:
        folders.append("tests")
    selected = [ROOT / name for name in TOP_FILES]
    for folder in folders:
        selected += [p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts
                     and (p.suffix.lower() in SUFFIXES or p.name == "LICENSE")]
    for source in selected:
        if source.is_symlink() or ROOT not in source.resolve().parents:
            parser.error("Refusing source symlink/out-of-tree path: " + str(source))
        if not source.is_file():
            parser.error("Required package file is missing: " + str(source))
    destination.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for source in sorted(set(selected)):
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Copy verification failed: " + str(relative))
        hashes[relative.as_posix()] = digest
    report = {"schema_version": 1, "package": "se050e-crypto-middleware",
              "with_tests": args.with_tests, "files_sha256": hashes,
              "excluded": ["BSP-specific application glue", "testdata", "private keys/certificates",
                           "firmware", "flash backups", "build outputs", "machine-local metadata"]}
    (destination / "PACKAGE_MANIFEST.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Exported and hash-verified {len(hashes)} source/document files: {destination}")
    print("Select your OS/board port and integrate the matching TLS hooks; this is not a prebuilt library.")


if __name__ == "__main__":
    main()
