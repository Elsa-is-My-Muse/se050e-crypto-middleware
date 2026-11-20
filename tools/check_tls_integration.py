"""Read-only hash check for the version-pinned low-level TLS/PSA integration patch."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def inspect(stack):
    manifest = json.loads((ROOT / "integration/mbedtls/manifest.json").read_text(encoding="utf-8"))
    result = []
    for item in manifest["files"]:
        source = stack / item["path"]
        status = "missing"
        if source.is_file():
            digest = hashlib.sha256(source.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
            status = ("patched" if digest == item["patched_sha256_lf"] else
                      "base" if digest == item["base_sha256_lf"] else "different")
        result.append({"file": item["path"], "status": status})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stack", type=Path, help="matching extern_mbedtls directory")
    parser.add_argument("--expect", choices=("base", "patched"), default="patched")
    args = parser.parse_args()
    result = inspect(args.stack.resolve())
    print(json.dumps(result, indent=2))
    if any(item["status"] != args.expect for item in result):
        parser.exit(1, "Mismatch: do not blindly apply/reapply the patch; inspect the selected stack version.\n")
    print("Low-level hooks match. Application identity/entropy/lifecycle hooks still require review/tests.")


if __name__ == "__main__":
    main()
