"""Check the source inventory, JSON files and local Markdown links using only Python."""
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")


def inspect(root):
    errors = []
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for key in ("core_sources", "middleware_sources", "reference_platform_sources"):
        for name in manifest[key]:
            if not (root / name).is_file():
                errors.append(f"{key}: missing file {name}")
    for key in ("core_include_dirs", "reference_os_include_dirs", "reference_platform_include_dirs"):
        for name in manifest[key]:
            if not (root / name).is_dir():
                errors.append(f"{key}: missing directory {name}")
    actual = {p.relative_to(root).as_posix() for folder in ("src", "nxp")
              for p in (root / folder).glob("*.c")}
    if actual != set(manifest["core_sources"]):
        errors.append("Core C source files differ from manifest.json")
    for name in ("LICENSE", "NOTICE", "README.md", "README.en.md", "CONTRIBUTING.md", "SECURITY.md"):
        if not (root / name).is_file():
            errors.append("Missing project file: " + name)
    json_files = [root / "manifest.json"]
    for folder in ("integration",):
        json_files.extend((root / folder).rglob("*.json"))
    package_manifest = root / "PACKAGE_MANIFEST.json"
    if package_manifest.is_file():
        json_files.append(package_manifest)
    for path in json_files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
    documents = list(root.glob("*.md"))
    for folder in ("integration", ".github"):
        documents.extend((root / folder).rglob("*.md"))
    for document in documents:
        for match in LINK.finditer(document.read_text(encoding="utf-8")):
            target = match.group(1).strip("<>")
            parts = urlsplit(target)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            linked = (document.parent / unquote(parts.path)).resolve()
            if root.resolve() != linked and root.resolve() not in linked.parents:
                errors.append(f"{document.relative_to(root)}: link escapes project: {target}")
            elif not linked.exists():
                errors.append(f"{document.relative_to(root)}: missing link target: {target}")
    return errors, len(documents), len(json_files)


def main():
    try:
        errors, documents, json_files = inspect(ROOT)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Project check failed: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Project check PASS: source inventory, {json_files} JSON files, {documents} Markdown files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
