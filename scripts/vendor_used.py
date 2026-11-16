#!/usr/bin/env python3
"""Vendor only the warpdotdev git dependencies used by the local source tree."""

import glob
import json
import os
import re
import shutil
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE = os.environ.get("SOURCE_DIR", "/workspaces/cognix-dev")
VENDOR = os.path.join(ROOT, "cognix-vendor")
CARGO_CACHE = os.path.expanduser("~/.cargo/git/checkouts")
VENDOR_GIT_URL = os.environ.get(
    "VENDOR_GIT_URL", "https://github.com/nrelab/cognix-vendor.git"
)

LOCK_RE = re.compile(
    r"git\+https://github\.com/warpdotdev/([^?]+?)(?:\.git)?\?[^#]+#([0-9a-f]{40})$"
)

GIT_URL_RE = re.compile(
    r'(git\s*=\s*)(["\'])https://github\.com/warpdotdev/[^"\']*\2'
)
VENDOR_PATH_RE = re.compile(
    r'path\s*=\s*(["\'])(?:\.\./)*cognix-vendor/[^"\']*\1'
)
PIN_INLINE_RES = [
    re.compile(r',\s*(?:rev|tag|branch)\s*=\s*"[^"]*"'),
    re.compile(r'(?:rev|tag|branch)\s*=\s*"[^"]*"\s*,\s*'),
    re.compile(r'(?:rev|tag|branch)\s*=\s*"[^"]*"'),
]
PIN_LINE_RE = re.compile(r"^\s*(?:rev|tag|branch)\s*=")


def _vendor_git_sub(match):
    return f'{match.group(1)}{match.group(2)}{VENDOR_GIT_URL}{match.group(2)}'


def rewrite_deps(text):
    """Point vendored deps at the vendor repo and drop upstream pins."""
    lines = text.splitlines()
    marked = [False] * len(lines)
    for i, line in enumerate(lines):
        if GIT_URL_RE.search(line):
            line = GIT_URL_RE.sub(_vendor_git_sub, line)
        elif VENDOR_PATH_RE.search(line):
            line = VENDOR_PATH_RE.sub(f'git = "{VENDOR_GIT_URL}"', line)
        else:
            continue
        for pin_re in PIN_INLINE_RES:
            line = pin_re.sub("", line)
        lines[i] = line
        marked[i] = True
    # Drop bare rev/tag/branch lines inside dep tables that had a rewrite.
    out = []
    section_marked = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("["):
            section_marked = False
        if marked[i]:
            section_marked = True
        if section_marked and PIN_LINE_RE.match(line):
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def package_paths(root):
    paths = {}
    for manifest in glob.glob(os.path.join(root, "**", "Cargo.toml"), recursive=True):
        if os.path.join("target", "") in manifest:
            continue
        try:
            with open(manifest, "rb") as handle:
                data = tomllib.load(handle)
        except (tomllib.TOMLDecodeError, OSError):
            continue
        name = data.get("package", {}).get("name")
        if not name:
            continue
        rel = os.path.relpath(os.path.dirname(manifest), root)
        paths.setdefault(name, rel if rel != "." else "")
    return paths


def main():
    lock = tomllib.load(open(os.path.join(SOURCE, "Cargo.lock"), "rb"))
    repos = {}
    for pkg in lock["package"]:
        match = LOCK_RE.match(pkg.get("source", ""))
        if not match:
            continue
        name, sha = match.groups()
        entry = repos.setdefault(name, {"sha": sha, "packages": set()})
        entry["packages"].add(pkg["name"])

    os.makedirs(VENDOR, exist_ok=True)
    manifest = []
    for name in sorted(repos):
        entry = repos[name]
        sha = entry["sha"]
        candidates = glob.glob(os.path.join(CARGO_CACHE, f"{name}-*", sha[:7]))
        if not candidates:
            raise SystemExit(f"no cached checkout for {name}@{sha[:12]}")
        src = candidates[0]
        dst = os.path.join(VENDOR, name)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(
            src,
            dst,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".cargo-ok"),
        )

        found = package_paths(dst)
        package_paths_out = {}
        for package in sorted(entry["packages"]):
            sub = found.get(package, "")
            package_paths_out[package] = os.path.join("cognix-vendor", name, sub)
        missing = [p for p in entry["packages"] if p not in found]
        if missing:
            print(f"  warning: manifest not found for {', '.join(missing)} in {name}")
        manifest.append(
            {
                "repo": name,
                "rev": sha,
                "packages": sorted(entry["packages"]),
                "package_paths": package_paths_out,
            }
        )
        print(f"vendored {name:28} {sha[:12]}  packages={len(entry['packages'])}")

    with open(os.path.join(VENDOR, "MANIFEST.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    def toml_quote(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    toml_lines = [
        "# Vendored sources used as git dependencies by cognix-dev.",
        "# Mirrors MANIFEST.json; regenerate via scripts/vendor_used.py.",
        "# Consumers reference crates as `<package> = { git = \"<git_url>\" }`.",
        "",
        f'git_url = "{VENDOR_GIT_URL}"',
        "",
    ]
    for item in manifest:
        toml_lines.append("[[vendor]]")
        toml_lines.append(f'repo = {toml_quote(item["repo"])}')
        toml_lines.append(f'rev = {toml_quote(item["rev"])}')
        toml_lines.append("packages = [")
        toml_lines += [f"  {toml_quote(p)}," for p in item["packages"]]
        toml_lines.append("]")
        toml_lines.append("[vendor.package_paths]")
        for package, path in item["package_paths"].items():
            toml_lines.append(f"{toml_quote(package)} = {toml_quote(path)}")
        toml_lines.append("")
    with open(os.path.join(VENDOR, "vendor.toml"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(toml_lines))

    with open(os.path.join(VENDOR, "SOURCES.md"), "w", encoding="utf-8") as handle:
        handle.write("# Vendored sources\n\n")
        handle.write("Only repositories used as git dependencies by `cognix-dev`.\n\n")
        handle.write("| Repo | Revision | Packages |\n")
        handle.write("| --- | --- | --- |\n")
        for item in manifest:
            handle.write(
                f"| {item['repo']} | `{item['rev'][:12]}` | "
                f"{', '.join(item['packages'])} |\n"
            )

    manifests = glob.glob(os.path.join(SOURCE, "**", "Cargo.toml"), recursive=True)
    manifests.append(os.path.join(ROOT, "Cargo.toml"))
    vendor_root = os.path.abspath(VENDOR) + os.sep
    for path in manifests:
        apath = os.path.abspath(path)
        if "target" in apath.split(os.sep) or apath.startswith(vendor_root):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            continue
        updated = rewrite_deps(text)
        if updated != text:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(updated)
            print(f"  rewrote deps in {os.path.relpath(path, ROOT)}")

    cargo_toml = os.path.join(ROOT, "Cargo.toml")
    with open(cargo_toml, encoding="utf-8") as handle:
        workspace_manifest = handle.read()
    if 'exclude = ["vendor"]' in workspace_manifest:
        workspace_manifest = workspace_manifest.replace(
            'exclude = ["vendor"]', 'exclude = ["cognix-vendor"]', 1
        )
    elif 'exclude = ["cognix-vendor"]' not in workspace_manifest:
        workspace_manifest = workspace_manifest.replace(
            "[workspace]\n", '[workspace]\nexclude = ["cognix-vendor"]\n', 1
        )
    with open(cargo_toml, "w", encoding="utf-8") as handle:
        handle.write(workspace_manifest)

    config = os.path.join(ROOT, ".cargo", "config.toml")
    with open(config, encoding="utf-8") as handle:
        base = handle.read()
    marker = "# >>> vendored warpdotdev patches >>>"
    base = base.split(marker)[0].rstrip() + "\n"
    with open(config, "w", encoding="utf-8") as handle:
        handle.write(base)

    print(f"\nvendored {len(manifest)} repos")


if __name__ == "__main__":
    main()
