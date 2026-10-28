#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory an iPhone backup and optionally copy WhatsApp chat database files.

This runs on a computer, not on an iPhone. It does not connect to a phone,
restore WhatsApp, decrypt encrypted backups, or undelete messages. It reads
the source backup without opening its databases in SQLite. SQLite is used
only on a temporary copy of the backup manifest. It never opens the copied
chat database, so its raw bytes and any available journals are preserved.

Usage:
    python3 inspect_backup.py
    python3 inspect_backup.py /path/to/one/backup
    python3 inspect_backup.py /path/to/one/backup --extract-to /new/folder

Use a completed backup which is not currently being updated. Preserve older
backups before creating a new backup. A backup made after deletion might
contain no deleted text. Missing files in a backup do not prove that those
files are absent from the phone. An encrypted backup requires its password
and a separate local decryption step. Do not disable encryption for this tool.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import sqlite3
import sys
import tempfile

from forensic_io import safe_path


DEFAULT_ROOT = Path.home() / "Library/Application Support/MobileSync/Backup"
TARGET_NAMES = {
    "ChatStorage.sqlite", "ChatStorage.sqlite-wal",
    "ChatStorage.sqlite-shm", "ChatStorage.sqlite-journal",
}
SQLITE_HEADER = b"SQLite format 3\x00"


def load_plist(path):
    if not path.is_file():
        return {}
    with path.open("rb") as stream:
        data = plistlib.load(stream)
    return data if isinstance(data, dict) else {}


def metadata(folder):
    info = load_plist(folder / "Info.plist")
    manifest = load_plist(folder / "Manifest.plist")
    status = load_plist(folder / "Status.plist")
    return {
        "backup_date": str(info.get("Last Backup Date", "unknown")),
        "iOS_version": info.get("Product Version", "unknown"),
        "device_model": info.get("Product Type", "unknown"),
        "encrypted": manifest.get("IsEncrypted", "unknown"),
        "snapshot_state": status.get("SnapshotState", "unknown"),
    }


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def manifest_rows(folder):
    """Read a temporary copy, including any manifest journal sidecars."""
    source = folder / "Manifest.db"
    with source.open("rb") as stream:
        if stream.read(16) != SQLITE_HEADER:
            raise ValueError("Manifest.db is encrypted or is not a SQLite database.")
    with tempfile.TemporaryDirectory(prefix="whatsapp-manifest-") as temp:
        copied = Path(temp) / "Manifest.db"
        for suffix in ("", "-wal", "-shm", "-journal"):
            original = folder / ("Manifest.db" + suffix)
            if original.is_file():
                shutil.copyfile(str(original), str(Path(temp) / original.name))
        connection = sqlite3.connect(copied.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute(
                "SELECT fileID, domain, relativePath FROM Files "
                "WHERE lower(domain) LIKE '%whatsapp%'"
            )
            return [tuple(row) for row in rows if row[2] and
                    PurePosixPath(row[2]).name in TARGET_NAMES]
        finally:
            connection.close()


def source_file(folder, file_id):
    if not isinstance(file_id, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", file_id):
        raise ValueError("Unexpected backup file identifier; refusing extraction.")
    for candidate in (safe_path(folder, file_id[:2] + "/" + file_id), safe_path(folder, file_id)):
        if candidate.is_symlink():
            raise ValueError("Backup payload is a symbolic link; refusing extraction.")
        if candidate.is_file():
            return candidate
    return None


def safe_relative(domain, relative_path):
    if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", domain):
        raise ValueError("Unexpected backup domain; refusing extraction.")
    parts = PurePosixPath(relative_path)
    if parts.is_absolute() or ".." in parts.parts or "\\" in relative_path:
        raise ValueError("Unsafe relative path in backup manifest.")
    return Path(domain, *parts.parts)


def inspect(folder, output):
    folder = folder.expanduser().resolve(strict=True)
    report = {"backup": metadata(folder), "files": []}
    print(json.dumps(report["backup"], indent=2))
    if report["backup"]["encrypted"] is True:
        print("Encrypted backup: local decryption with its backup password is required.")
        print("No files were extracted; the source was not changed.")
        return 3
    if report["backup"]["snapshot_state"] not in ("finished", "unknown"):
        raise ValueError("Backup may be incomplete or updating; inspect a completed copy.")
    rows = manifest_rows(folder)
    for file_id, domain, relative_path in rows:
        relative = safe_relative(domain, relative_path)
        payload = source_file(folder, file_id)
        report["files"].append({
            "path": str(relative),
            "present": payload is not None,
            "size": payload.stat().st_size if payload else None,
            "file_id": file_id,
        })
    print("WhatsApp chat database/log entries found:", len(rows))
    for item in report["files"]:
        print(json.dumps({k: v for k, v in item.items() if k != "file_id"}))
    if not rows:
        print("No matching files in this backup. This is not a conclusion about the phone.")
        return 0
    if output is None:
        return 0
    output = output.expanduser().resolve()
    if output == folder or folder in output.parents or output in folder.parents:
        raise ValueError("Extraction destination must be outside the source backup.")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report["complete"] = False
    try:
        for item in report["files"]:
            if not item["present"]:
                continue
            payload = source_file(folder, item["file_id"])
            destination = safe_path(output, item["path"])
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            before = digest(payload)
            with payload.open("rb") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            os.chmod(str(destination), 0o600)
            after = digest(payload)
            copied = digest(destination)
            item["sha256"] = copied
            if before != after or before != copied:
                raise ValueError("A source file changed or copy verification failed; preserve this attempt and retry on a stable backup.")
        report["complete"] = all(item["present"] for item in report["files"])
    finally:
        report_path = output / "extraction-report.json"
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        os.chmod(str(report_path), 0o600)
    print("Byte copies and SHA-256 hashes saved to:", output)
    print("These are preserved files, not recovered or restored messages.")
    return 0 if report["complete"] else 4


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("backup", nargs="?", type=Path)
    parser.add_argument("--extract-to", type=Path,
                        help="New destination folder; existing folders are never overwritten")
    args = parser.parse_args()
    if args.extract_to and args.backup is None:
        parser.error("--extract-to requires the path to one backup")
    try:
        if args.backup:
            return inspect(args.backup, args.extract_to)
        if not DEFAULT_ROOT.exists():
            print("No backup folder at the standard Mac location.")
            return 0
        folders = sorted(p for p in DEFAULT_ROOT.iterdir()
                         if p.is_dir() and (p / "Info.plist").is_file())
        print("Local iPhone backups found:", len(folders))
        for index, folder in enumerate(folders, 1):
            print(json.dumps({"backup_number": index, "folder": str(folder),
                              **metadata(folder)}, indent=2))
        return 0
    except PermissionError:
        print("Access blocked by macOS. Use Finder to copy the selected backup into an accessible folder, then pass that copy's path. No permission settings were changed.", file=sys.stderr)
        return 2
    except (OSError, ValueError, sqlite3.Error, plistlib.InvalidFileException) as error:
        print("Inspection stopped:", str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
