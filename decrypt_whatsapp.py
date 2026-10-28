#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Extract preserved WhatsApp database/log files from a completed capture.

Run in your own Terminal with the optional capture dependencies installed. If encrypted,
the Finder backup password is requested with hidden input. It is not printed,
saved, accepted as a command-line argument, or sent over the network.

No original backup files or chat databases are opened for writing. A temporary
copy of the manifest is examined; database/log payloads are decrypted into a
fresh, private output directory. The script does not open the chat databases
in SQLite, recover deleted messages, or restore anything to a phone.

With no backup path argument, the newest successfully completed capture in
this task is selected. --list only shows completed capture metadata.
--inventory-only lists all WhatsApp paths recorded in the backup index, so
additional database copies can be identified even if not captured yet.
"""

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import sys
import tempfile
import time

from related_data_rules import is_related_file, load_media_inventory
from forensic_io import safe_path


ROOT = Path(__file__).resolve().parent
NAMES = {"ChatStorage.sqlite", "ChatStorage.sqlite-wal", "ChatStorage.sqlite-shm",
         "ChatStorage.sqlite-journal"}
RESERVE = 1536 * 1024 * 1024


def completed_backups():
    found = []
    for state_file in sorted((ROOT / "captures").glob("*/capture-state.json"), reverse=True):
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state.get("status") != "stream_completed":
            continue
        if state.get("include_related") and not state.get("related_targets_present"):
            continue
        for manifest in sorted(state_file.parent.glob("*/Manifest.plist")):
            if (manifest.parent / "Manifest.db").is_file():
                found.append(manifest.parent)
    return found


def wait_for_capture(folder, timeout=1800):
    folder = folder.expanduser().resolve(strict=True)
    deadline = time.monotonic() + timeout
    print("Waiting for the ongoing capture to finish. The backup password will be requested afterward.", flush=True)
    while True:
        state_path = folder / "capture-state.json"
        if state_path.is_file():
            state = json.loads(state_path.read_text())
            if state.get("status") != "stream_completed":
                raise ValueError("The capture did not complete; no password or decryption was requested.")
            if state.get("include_related") and not state.get("related_targets_present"):
                raise ValueError("The extra files were not verified in this capture. Preserve it and use the corrected capture.")
            manifests = [p for p in folder.glob("*/Manifest.plist")
                         if (p.parent / "Manifest.db").is_file()]
            if len(manifests) != 1:
                raise ValueError("Expected one completed iPhone capture.")
            return [manifests[0].parent]
        if time.monotonic() >= deadline:
            raise ValueError("Capture wait timed out; originals are preserved.")
        time.sleep(2)


def decode_payload(raw, encrypted, keybag=None, key=None):
    if not encrypted or not raw:
        return raw
    from cryptography.hazmat.primitives import padding
    padded = keybag.decrypt(raw, key)
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def manifest_entries(source, manifest, keybag, all_whatsapp=False):
    data = safe_path(source, "Manifest.db").read_bytes()
    if manifest.is_encrypted:
        data = keybag.decrypt(data, manifest.manifest_key)
    if data[:16] != b"SQLite format 3\x00":
        raise ValueError("The backup manifest could not be decoded as SQLite.")
    with tempfile.TemporaryDirectory(prefix="wa-manifest-read-") as temp:
        copied = Path(temp) / "Manifest.db"
        copied.write_bytes(data)
        os.chmod(str(copied), 0o600)
        # Plaintext manifest journals, if supplied, belong beside the temporary
        # copy. Encrypted complete captures are read from their final manifest.
        if not manifest.is_encrypted:
            for suffix in ("-wal", "-shm", "-journal"):
                original = source / ("Manifest.db" + suffix)
                if original.is_file():
                    shutil.copyfile(str(original), str(Path(temp) / original.name))
        connection = sqlite3.connect(copied.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            query = ("SELECT fileID,domain,relativePath,file FROM Files "
                     "WHERE lower(domain) LIKE '%whatsapp%'")
            if not all_whatsapp:
                query += " AND relativePath LIKE '%ChatStorage.sqlite%'"
            return [tuple(row) for row in connection.execute(query)
                    if isinstance(row[2], str) and
                    (all_whatsapp or PurePosixPath(row[2]).name in NAMES)]
        finally:
            connection.close()


def inventory(source, destination, manifest, keybag):
    """Save paths and sizes only; never serialize backup encryption keys."""
    from bpylist2 import archiver
    from pyiosbackup.manifest_dbs.sqlite3 import MBFile  # noqa: F401
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError("Output must be separate from the source backup.")
    manifest_hash = hashlib.sha256((source / "Manifest.db").read_bytes()).hexdigest()
    rows = manifest_entries(source, manifest, keybag, all_whatsapp=True)
    entries = []
    for file_id, domain, relative_path, metadata_blob in rows:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", file_id):
            raise ValueError("Unexpected backup file identifier.")
        metadata = archiver.unarchive(metadata_blob) if metadata_blob else None
        payload = safe_path(source, file_id[:2] + "/" + file_id)
        if not payload.is_file():
            payload = safe_path(source, file_id)
        present = payload.is_file() and not payload.is_symlink()
        candidate = bool(re.search(
            r"(?i)(sqlite|chatstorage|chatbackup|database|backup|\.db(?:$|[.-])|\.bak$)",
            relative_path))
        entries.append({"domain": domain, "relative_path": relative_path,
                        "file_id": file_id, "captured_payload": present,
                        "captured_bytes": payload.stat().st_size if present else None,
                        "declared_bytes": getattr(metadata, "size", None),
                        "database_or_backup_candidate": candidate})
    unchanged = hashlib.sha256((source / "Manifest.db").read_bytes()).hexdigest() == manifest_hash
    if not unchanged:
        raise ValueError("Backup index changed while it was being read.")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"source_backup": str(source), "manifest_sha256": manifest_hash,
              "original_manifest_unchanged": unchanged,
              "note": "Paths in a partial backup index do not imply their payloads were captured. Keys and passwords are not included.",
              "whatsapp_entries": len(entries), "files": entries}
    with (destination / "whatsapp-file-inventory.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("WhatsApp index entries examined:", len(entries))
    print("Database/backup candidates:", sum(item["database_or_backup_candidate"] for item in entries))
    print("Inventory saved to:", destination)
    print("Original files were preserved. This check did not connect to or change the iPhone.")
    return 0


def export(source, destination, manifest, keybag, include_related=False, media_inventory=None):
    from bpylist2 import archiver
    # Importing MBFile registers Apple's metadata class with bpylist2.
    from pyiosbackup.manifest_dbs.sqlite3 import MBFile  # noqa: F401
    rows = manifest_entries(source, manifest, keybag, all_whatsapp=include_related)
    if include_related:
        media = load_media_inventory(media_inventory) if media_inventory else {}
        rows = [row for row in rows if is_related_file(row[1], row[2]) or row[0] in media]
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError("Output must be separate from the source backup.")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"source_backup": str(source), "encrypted_source": manifest.is_encrypted,
              "include_related": include_related,
              "media_inventory": str(media_inventory) if media_inventory else None,
              "files": [], "complete": False, "deleted_messages_recovered": "not yet examined"}
    try:
        for file_id, domain, relative_path, metadata_blob in rows:
            if not re.fullmatch(r"[0-9a-fA-F]{40}", file_id):
                raise ValueError("Unexpected backup file identifier.")
            relative = PurePosixPath(relative_path)
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", domain) or relative.is_absolute() or ".." in relative.parts or "\\" in relative_path:
                raise ValueError("Unexpected path in backup metadata.")
            payload = safe_path(source, file_id[:2] + "/" + file_id)
            if not payload.is_file():
                payload = safe_path(source, file_id)
            entry = {"path": str(Path(domain, *relative.parts)), "present": payload.is_file()}
            report["files"].append(entry)
            if not entry["present"]:
                continue
            if payload.is_symlink():
                raise ValueError("Refusing a symbolic-link payload.")
            metadata = archiver.unarchive(metadata_blob)
            ciphertext = payload.read_bytes()
            entry["source_sha256"] = hashlib.sha256(ciphertext).hexdigest()
            clear = decode_payload(ciphertext, manifest.is_encrypted, keybag, metadata.encryption_key)
            if relative.name == "ChatStorage.sqlite" and clear[:16] != b"SQLite format 3\x00":
                raise ValueError("The chat database did not decode as SQLite; originals remain preserved.")
            if shutil.disk_usage(str(destination)).free - len(clear) < RESERVE:
                raise OSError("Not enough space to extract this file while retaining 1.5 GiB free.")
            target = safe_path(destination, entry["path"])
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(clear)
            os.chmod(str(target), 0o600)
            entry["decrypted_bytes"] = len(clear)
            entry["declared_bytes"] = metadata.size
            entry["sha256"] = hashlib.sha256(clear).hexdigest()
            if hashlib.sha256(payload.read_bytes()).hexdigest() != entry["source_sha256"]:
                raise ValueError("Source changed during extraction; preserve this attempt and retry on a stable capture.")
        report["complete"] = bool(rows) and all(item["present"] for item in report["files"])
    finally:
        with (destination / "extraction-report.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print("Database/log files extracted:", sum(item.get("decrypted_bytes") is not None for item in report["files"]))
    print("Output:", destination)
    print("Original files were preserved. Deleted-message recovery has not yet been attempted.")
    if not rows:
        print("This capture does not list the chat database. That does not establish what remains on the phone.")
    return 0 if report["complete"] else 4


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("backup", nargs="?", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--inventory-only", action="store_true",
                        help="Inspect all WhatsApp paths in the existing capture; do not extract chat files")
    parser.add_argument("--include-related", action="store_true",
                        help="Extract related WhatsApp databases, indexes and support files retained by the broader capture")
    parser.add_argument("--media-inventory", type=Path,
                        help="Also extract the small explicit list of retained WhatsApp media paths")
    parser.add_argument("--wait-for-capture", type=Path,
                        help="Wait for this capture folder to complete before requesting the password")
    args = parser.parse_args()
    if args.media_inventory and not args.include_related:
        parser.error("Media extraction requires --include-related.")
    media_inventory = args.media_inventory.expanduser().resolve(strict=True) if args.media_inventory else None
    if args.wait_for_capture and args.backup:
        parser.error("Use either an explicit backup or --wait-for-capture.")
    try:
        if args.wait_for_capture:
            backups = wait_for_capture(args.wait_for_capture)
        else:
            backups = completed_backups() if args.backup is None else [args.backup.expanduser().resolve(strict=True)]
    except (OSError, ValueError) as error:
        print("Capture check stopped:", error, file=sys.stderr)
        return 2
    if args.list:
        print("Completed captures with a manifest:", len(backups))
        for index, backup in enumerate(backups, 1):
            print(str(index) + ": " + backup.parent.name)
        return 0
    if not backups:
        print("No completed capture is available yet. Wait for the capture to finish.", file=sys.stderr)
        return 2
    source = backups[0]
    if len(backups) > 1:
        parser.error("Multiple completed captures found; supply the explicit backup directory.")
    from pyiosbackup.keybag import Keybag
    from pyiosbackup.manifest_plist import ManifestPlist
    manifest = ManifestPlist.from_path(source / "Manifest.plist")
    keybag = None
    if manifest.is_encrypted:
        password = None
        if password is None:
            if not sys.stdin.isatty():
                print("Run this script in your own Terminal so the backup password can be entered privately with hidden input.", file=sys.stderr)
                return 2
            print("Enter the Finder/iPhone local-backup password, not your Apple Account password.")
            password = getpass.getpass("Backup password (hidden): ")
        try:
            keybag = Keybag.from_manifest(manifest, password)
        except Exception:
            print("Could not unlock the backup. Check its local-backup password; no original files were changed.", file=sys.stderr)
            return 2
        finally:
            password = None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ")
    prefix = "inventory-" if args.inventory_only else "extracted-"
    destination = (args.destination or ROOT / (prefix + stamp)).expanduser().resolve()
    previous_umask = os.umask(0o077)
    try:
        if args.inventory_only:
            return inventory(source, destination, manifest, keybag)
        return export(source, destination, manifest, keybag, args.include_related, media_inventory)
    except (OSError, ValueError, sqlite3.Error) as error:
        print("Extraction stopped:", str(error), file=sys.stderr)
        return 2
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
