#!/usr/bin/env python3
"""Copy actual license texts from pnpm's installed frontend dependency graph."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

web, inventory, all_inventory, bundle = map(lambda value: Path(value).resolve(), sys.argv[1:])
records = json.loads(inventory.read_text())
packages = {Path(path).resolve() for group in records.values() for entry in group for path in entry["paths"]}
# These build dependencies can emit runtime helper code or CSS into the output.
helpers = {"vite", "rolldown", "tailwindcss"}
all_records = [entry for group in json.loads(all_inventory.read_text()).values() for entry in group]
if not helpers <= {entry["name"] for entry in all_records}:
    raise RuntimeError("Missing bundler runtime notices")
packages.update(Path(path).resolve() for entry in all_records if entry["name"] in helpers for path in entry["paths"])
notice_name = re.compile(r"^(licen[sc]e|notice|copying|copyright|patents|authors)([._-].*)?$", re.I)
manifest = {
    "format": 1,
    "scope": "Authelia production dependency graph plus Vite/Rolldown/Tailwind runtime attribution",
    "lockfile_sha256": hashlib.sha256((web / "pnpm-lock.yaml").read_bytes()).hexdigest(),
    "packages": {},
}
for directory in sorted(packages):
    directory.relative_to(web / "node_modules")
    package = json.loads((directory / "package.json").read_text())
    identifier = package["name"] + "@" + package["version"]
    if identifier in manifest["packages"]:
        continue
    notices = sorted(p for p in directory.rglob("*") if p.is_file() and notice_name.match(p.name))
    # Some upstream npm packages put their full MIT grant in README.md.
    notices += [p for p in sorted(directory.glob("README*")) if p.is_file()
                and "Permission is hereby granted, free of charge" in p.read_text(errors="replace")
                and "IN NO EVENT" in p.read_text(errors="replace")]
    if not notices:
        raise RuntimeError(f"Missing license/notice text for {identifier}")
    entry = {"license": package["license"], "files": {}}
    for path in notices:
        target = bundle / "licenses" / "authelia-web" / identifier / path.relative_to(directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o644)
        entry["files"][str(target.relative_to(bundle))] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest["packages"][identifier] = entry
destination = bundle / "metadata" / "authelia-web-notices.json"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"Packaged frontend notices for {len(manifest['packages'])} packages")
