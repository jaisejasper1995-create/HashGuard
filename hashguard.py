
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_folder(folder):
    """Return relative file paths and their SHA-256 fingerprints."""
    results = {}
    folder = Path(folder)

    for root, dirs, files in os.walk(folder, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if not (Path(root) / name).is_symlink()
        )

        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink():
                raise ValueError(f"Symbolic links are unsupported: {path}")

            relative_path = path.relative_to(folder).as_posix()
            results[relative_path] = calculate_sha256(path)

    return results


def validate_baseline(baseline):
    if not isinstance(baseline, dict):
        return False

    if baseline.get("schema_version") != "1.0":
        return False

    files = baseline.get("files")
    if not isinstance(files, dict):
        return False

    for name, fingerprint in files.items():
        if (
            not isinstance(name, str)
            or not name
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            return False

    return True


def validate_paths(folder, baseline_path):
    folder = Path(folder)
    baseline_path = Path(baseline_path)

    if not folder.is_dir():
        print("ERROR: Monitored folder does not exist.")
        return False

    resolved_folder = folder.resolve()
    resolved_baseline = baseline_path.resolve()

    if resolved_baseline.is_relative_to(resolved_folder):
        print("ERROR: Baseline must be outside the monitored folder.")
        return False

    if baseline_path.is_symlink():
        print("ERROR: Symbolic-link baselines are unsupported.")
        return False

    return True


def create_baseline(folder, baseline_path):
    if not validate_paths(folder, baseline_path):
        return 2

    baseline_path = Path(baseline_path)

    if baseline_path.exists():
        print("ERROR: Baseline already exists. Nothing overwritten.")
        return 2

    fingerprints = scan_folder(folder)
    baseline = {
        "schema_version": "1.0",
        "files": fingerprints,
    }

    with baseline_path.open("x", encoding="utf-8") as output:
        json.dump(baseline, output, indent=2)
        output.write("\n")

    print(f"PASS: Folder baseline created ({len(fingerprints)} files).")
    return 0


def verify_folder(folder, baseline_path):
    if not validate_paths(folder, baseline_path):
        return 2

    baseline_path = Path(baseline_path)

    if not baseline_path.is_file():
        print("ERROR: Baseline not found.")
        return 2

    with baseline_path.open("r", encoding="utf-8") as source:
        baseline = json.load(source)

    if not validate_baseline(baseline):
        print("ERROR: Invalid baseline format.")
        return 2

    expected = baseline["files"]
    actual = scan_folder(folder)

    expected_names = set(expected)
    actual_names = set(actual)

    missing = sorted(expected_names - actual_names)
    added = sorted(actual_names - expected_names)
    modified = sorted(
        name for name in expected_names & actual_names
        if expected[name] != actual[name]
    )

    for name in missing:
        print(f"FAIL: MISSING: {name}")

    for name in added:
        print(f"FAIL: ADDED: {name}")

    for name in modified:
        print(f"FAIL: MODIFIED: {name}")

    if missing or added or modified:
        print(
            f"FAIL: {len(missing)} missing, "
            f"{len(added)} added, {len(modified)} modified."
        )
        return 1

    print(f"PASS: Folder integrity verified ({len(actual)} files).")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="HashGuard folder integrity checker"
    )
    parser.add_argument("mode", choices=["create", "verify"])
    parser.add_argument("folder", help="Folder to monitor")
    parser.add_argument("baseline", help="JSON baseline outside the folder")

    args = parser.parse_args()

    try:
        if args.mode == "create":
            return create_baseline(args.folder, args.baseline)
        return verify_folder(args.folder, args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
