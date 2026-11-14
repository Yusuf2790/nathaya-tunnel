#!/usr/bin/env python3
"""Offline explicit-policy packager. No git, network, publication or installer execution."""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys


def local_validator():
    path = Path(os.path.abspath(__file__)).parent.parent / "updater/release.py"
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Symlink in trusted tool path")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Unsafe trusted validator")
    spec = importlib.util.spec_from_file_location("nathaya_builder_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description="Build nathaya-vVERSION.tar.gz from the trusted local policy")
    parser.add_argument("--source", type=Path, default=Path(os.path.abspath(__file__)).parent.parent)
    parser.add_argument("--output-dir", type=Path, required=True, help="Existing output directory; never overwrites")
    args = parser.parse_args()
    try:
        validator = local_validator()
        # Policy belongs to this trusted tool checkout, NOT a candidate archive/source.
        policy_path = Path(os.path.abspath(__file__)).parent.parent / "updater/release-policy.json"
        policy = validator.load_policy(validator.read_regular(policy_path, validator.MAX_MANIFEST))
        identity, blob = validator.build_artifact(args.source, policy)
        output_dir = Path(os.path.abspath(args.output_dir))
        validator.safe_path(output_dir)
        validator.require(output_dir.is_dir(), "Output directory does not exist")
        artifact = output_dir / f"nathaya-v{identity}.tar.gz"
        validator.safe_path(artifact)
        fd = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(blob)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            artifact.unlink()
            raise
        print(artifact.name)
        print("sha256:" + validator.sha256(blob))
        print("Local checksum only; clients require the GitHub asset metadata digest.")
        return 0
    except (ValueError, OSError):
        print("BLOCKED: packaging failed; inspect trusted policy, explicit source files, VERSION and syntax.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
