#!/usr/bin/env python3
"""Build the AgentCore deployment zip for the dissertation experiment agent.

What it does (and only this):
  1. ``pip download`` the pinned wheels from requirements.txt for
     CPython 3.12 / manylinux2014_aarch64 into build/deps/
  2. Extract the wheels plus runtime_main.py, engine.py, config.json
     (at the zip root) into a staging dir
  3. Zip the staging dir into build/agent.zip
  4. Write build/package_manifest.json with hashes and dependency versions

Creates NO AWS resources -- packaging only.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ("runtime_main.py", "engine.py", "config.json")
PLATFORM = "manylinux2014_aarch64"
PYTHON_VERSION = "3.12"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pip_download(requirements, deps_dir):
    cmd = [
        sys.executable, "-m", "pip", "download",
        "-r", requirements,
        "--platform", PLATFORM,
        "--python-version", PYTHON_VERSION,
        "--only-binary=:all:",
        "-d", deps_dir,
    ]
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def _wheel_name_version(filename):
    # Wheel filename: {distribution}-{version}(-{build})?-{pytag}-{abitag}-{platform}.whl
    # Distribution and version never contain '-', so split from the right.
    # e.g. boto3-1.43.108-py3-none-any.whl -> ("boto3", "1.43.108")
    stem = filename[:-4] if filename.endswith(".whl") else filename
    parts = stem.split("-")
    if len(parts) < 5:
        return None
    pytag, abitag, platform = parts[-3], parts[-2], parts[-1]
    rest = parts[:-3]
    if len(rest) == 3:  # build tag present: name-version-build
        rest = rest[:2]
    if len(rest) != 2:
        return None
    return rest[0].replace("_", "-").lower(), rest[1]


def main():
    ap = argparse.ArgumentParser(
        description="Package the dissertation experiment agent for AgentCore "
                    "(wheels for cp312/manylinux2014_aarch64 + runtime sources)."
    )
    ap.add_argument("--output", default=os.path.join(HERE, "build", "agent.zip"),
                    help="Path of the zip to build (default: build/agent.zip)")
    ap.add_argument("--deps-dir", default=os.path.join(HERE, "build", "deps"),
                    help="Directory for downloaded wheels (default: build/deps)")
    ap.add_argument("--stage-dir", default=os.path.join(HERE, "build", "pkg"),
                    help="Staging dir assembled into the zip (default: build/pkg)")
    ap.add_argument("--manifest", default=os.path.join(HERE, "build", "package_manifest.json"),
                    help="Manifest path (default: build/package_manifest.json)")
    ap.add_argument("--requirements", default=os.path.join(HERE, "requirements.txt"),
                    help="Requirements file (default: requirements.txt)")
    args = ap.parse_args()

    for d in (args.deps_dir, args.stage_dir, os.path.dirname(args.output),
              os.path.dirname(args.manifest)):
        os.makedirs(d, exist_ok=True)

    # 1. Download pinned wheels for the AgentCore runtime platform.
    _pip_download(args.requirements, args.deps_dir)

    # 2. Stage: extract wheels at zip root (Lambda-style layout) + sources.
    if os.path.isdir(args.stage_dir):
        shutil.rmtree(args.stage_dir)
    os.makedirs(args.stage_dir)
    dependency_versions = {}
    for wheel in sorted(os.listdir(args.deps_dir)):
        if not wheel.endswith(".whl"):
            continue
        nv = _wheel_name_version(wheel)
        if nv:
            dependency_versions[nv[0]] = nv[1]
        with zipfile.ZipFile(os.path.join(args.deps_dir, wheel)) as zf:
            zf.extractall(args.stage_dir)
    source_hashes = {}
    for src in SOURCES:
        src_path = os.path.join(HERE, src)
        shutil.copy2(src_path, os.path.join(args.stage_dir, src))
        source_hashes[src] = _sha256(src_path)

    # 3. Zip the staging dir (sources at zip root).
    if os.path.exists(args.output):
        os.remove(args.output)
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(args.stage_dir):
            for f in sorted(files):
                full = os.path.join(root, f)
                arc = os.path.relpath(full, args.stage_dir)
                zf.write(full, arc)

    package_sha256 = _sha256(args.output)
    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "platform": PLATFORM,
        "python_version": PYTHON_VERSION,
        "package": os.path.basename(args.output),
        "package_sha256": package_sha256,
        "source_hashes": source_hashes,
        "dependency_versions": dependency_versions,
    }
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")

    print("wrote %s (sha256 %s)" % (args.output, package_sha256[:16] + "..."), flush=True)
    print("wrote %s" % args.manifest, flush=True)


if __name__ == "__main__":
    main()
