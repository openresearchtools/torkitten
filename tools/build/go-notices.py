#!/usr/bin/env python3
"""Package notices from exact linked Go modules; never rebuild a binary."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

source, bundle, cache = map(lambda value: Path(value).resolve(), sys.argv[1:])
env = dict(os.environ, GOMODCACHE=str(cache), GOTOOLCHAIN="local", GOTELEMETRY="off")


def go(*args):
    return subprocess.check_output(["go", *args], cwd=bundle, env=env, text=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


notice_name = re.compile(r"^(licen[sc]e|notice|copying|copyright|patents|authors)([._-].*)?$", re.I)
manifest = {"format": 1, "binaries": {}, "modules": {}}


def collect(identifier, directory, provenance, root_only=False):
    if identifier in manifest["modules"]:
        return identifier
    paths = directory.iterdir() if root_only else directory.rglob("*")
    notices = sorted(p for p in paths if p.is_file() and notice_name.match(p.name))
    if not notices:
        raise RuntimeError(f"No license/notice files found for {identifier}")
    record = {"source": provenance, "files": {}}
    for path in notices:
        relative = path.relative_to(directory)
        target = bundle / "licenses" / "go-modules" / identifier / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o644)
        record["files"][str(target.relative_to(bundle))] = sha(target)
    manifest["modules"][identifier] = record
    return identifier


local = {
    "torkitten": ".",
    "github.com/caddyserver/caddy/v2": "third-party/caddy",
    "github.com/authelia/authelia/v4": "third-party/authelia",
    "./third-party/chisel": "third-party/chisel",
    "./third-party/age": "third-party/age",
    "./third-party/gozxing": "third-party/gozxing",
}
compiler = go("env", "GOVERSION").strip()
goroot = Path(go("env", "GOROOT").strip())
stdlib = collect(compiler, goroot, {"toolchain": compiler})
for binary in ("torkitten", "caddy", "authelia"):
    path = bundle / "bin" / binary
    info = json.loads(go("version", "-m", "-json", str(path)))
    if info["GoVersion"] != compiler:
        raise RuntimeError(f"Use {info['GoVersion']} to package {binary}'s standard library notices")
    record = {"sha256": sha(path), "go_version": compiler, "stdlib": stdlib, "modules": []}
    for declared in [info["Main"], *info["Deps"]]:
        dep = declared.get("Replace", declared)
        module, version = dep["Path"], dep["Version"]
        if version == "(devel)":
            directory = source / local[module]  # Unknown local replacements fail closed.
            provenance = {"path": str(directory.relative_to(source))}
            if module != "torkitten":
                lock = directory.with_suffix(".upstream.toml")
                pin = tomllib.loads(lock.read_text())
                provenance.update({key: pin[key] for key in ("upstream", "release", "commit", "tree")})
                identifier = declared["Path"] + "@" + pin["release"]
            else:
                identifier = "torkitten"
        else:
            identifier = module + "@" + version
            downloaded = json.loads(go("mod", "download", "-json", identifier))
            if downloaded.get("Sum") != dep["Sum"]:
                raise RuntimeError(f"Linked module checksum mismatch: {identifier}")
            directory = Path(downloaded["Dir"])
            provenance = {"module": module, "version": version, "sum": dep["Sum"]}
        record["modules"].append(collect(identifier, directory, provenance, module == "torkitten"))
        notices = manifest["modules"][identifier]
        if any("Mozilla Public License" in (bundle / name).read_text(errors="replace")[:300]
               for name in notices["files"]):
            if version == "(devel)":
                raise RuntimeError(f"MPL source packaging needs a versioned module: {identifier}")
            archive = bundle / "sources" / "go-modules" / (identifier + ".zip")
            archive.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(downloaded["Zip"], archive)
            archive.chmod(0o644)
            notices["source"].update({"archive": str(archive.relative_to(bundle)), "archive_sha256": sha(archive)})
    manifest["binaries"][binary] = record

destination = bundle / "metadata" / "go-notices.json"
destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"Packaged notices for {len(manifest['modules'])} Go source identities: {destination}")
