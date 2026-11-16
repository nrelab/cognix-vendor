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

LOCK_RE = re.compile(
    r"git\+https://github\.com/warpdotdev/([^?]+?)(?:\.git)?\?[^#]+#([0-9a-f]{40})$"
)
URL_RE = re.compile(r"https://github\.com/warpdotdev/[A-Za-z0-9_.-]+")


def repo_of(url):
    name = url.rsplit("/", 1)[-1]
    return name[:-4] if name.endswith(".git") else name


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
        entry = repos.setdefault(
            name, {"sha": sha, "packages": set(), "urls": set()}
        )
        entry["packages"].add(pkg["name"])
        entry["urls"].update(
            (
                f"https://github.com/warpdotdev/{name}",
                f"https://github.com/warpdotdev/{name}.git",
            )
        )

    used_urls = set()
    for manifest in glob.glob(os.path.join(SOURCE, "**", "Cargo.toml"), recursive=True):
        with open(manifest, encoding="utf-8") as handle:
            used_urls.update(URL_RE.findall(handle.read()))

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

        urls = sorted(u for u in entry["urls"] if repo_of(u) == name and u in used_urls)
        if not urls:
            urls = [f"https://github.com/warpdotdev/{name}"]
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
                "url": f"https://github.com/warpdotdev/{name}",
                "rev": sha,
                "packages": sorted(entry["packages"]),
                "patch_urls": urls,
                "package_paths": package_paths_out,
            }
        )
        print(f"vendored {name:28} {sha[:12]}  packages={len(entry['packages'])}")

    with open(os.path.join(VENDOR, "MANIFEST.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    with open(os.path.join(VENDOR, "SOURCES.md"), "w", encoding="utf-8") as handle:
        handle.write("# Vendored warpdotdev sources\n\n")
        handle.write("Only repositories used as git dependencies by `cognix-dev`.\n\n")
        handle.write("| Repo | Revision | Packages | Patch URL |\n")
        handle.write("| --- | --- | --- | --- |\n")
        for item in manifest:
            handle.write(
                f"| [{item['repo']}]({item['url']}) | `{item['rev'][:12]}` | "
                f"{', '.join(item['packages'])} | `{item['patch_urls'][0]}` |\n"
            )

    cargo_toml = os.path.join(ROOT, "Cargo.toml")
    with open(cargo_toml, encoding="utf-8") as handle:
        original_text = handle.read()
    with open(os.path.join(SOURCE, "Cargo.toml"), encoding="utf-8") as handle:
        data = tomllib.loads(handle.read())
    local_paths = {
        package: path
        for item in manifest
        for package, path in item["package_paths"].items()
    }
    crates_io_patched = {
        package
        for package, spec in data.get("patch", {}).get("crates-io", {}).items()
        if isinstance(spec, dict) and "warpdotdev" in spec.get("git", "")
    }
    rewritten = []
    in_crates_patch = False
    for line in original_text.splitlines():
        if line.startswith("["):
            in_crates_patch = line.strip() == "[patch.crates-io]"
        if in_crates_patch:
            for package in crates_io_patched:
                if line.startswith(f"{package} = "):
                    line = f'{package} = {{ path = "{local_paths[package]}" }}'
                    break
        rewritten.append(line)
    workspace_manifest = "\n".join(rewritten) + "\n"
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
    lines = [base, "", marker]
    for item in manifest:
        entries = {
            package: path
            for package, path in item["package_paths"].items()
            if package not in crates_io_patched
        }
        if not entries:
            continue
        for url in item["patch_urls"]:
            lines.append(f'[patch."{url}"]')
            for package, path in entries.items():
                lines.append(f'{package} = {{ path = "{path}" }}')
            lines.append("")
    lines.append("# <<< vendored warpdotdev patches <<<")
    with open(config, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    print(f"\nvendored {len(manifest)} repos, updated {config}")


if __name__ == "__main__":
    main()
