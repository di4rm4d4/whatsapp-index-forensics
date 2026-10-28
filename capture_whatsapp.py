#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep WhatsApp chat database payloads from an iPhone backup stream.

Requires the optional dependencies in requirements-capture.txt. By default this only prints
the planned operation; add --run to capture. A fresh destination is required.
The phone still transmits its full backup stream, but other app payloads are
discarded in memory by pymobiledevice3 instead of stored on this computer.

This calls only `backup2 backup`, with filters. It does not call restore,
erase, encryption changes, manifest pruning, or local backup deletion. It
does not request the backup password; existing encryption is preserved.
The result is a partial extraction, unsuitable for restoring a whole phone.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from related_data_rules import RELATED_PATTERN, load_related_inventory


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
MIN_FREE_BYTES = 1536 * 1024 * 1024
JOURNAL_PATTERN = r"(?i)whatsapp.*ChatStorage\.sqlite-journal$"


def command_for(destination, udid=None, filtered_capacity=None, space_guard=None, include_related=False, related_inventory=None, media_inventory=None):
    if include_related and (filtered_capacity is None or related_inventory is None):
        raise ValueError("Related capture requires the verified receiver and file inventory.")
    if filtered_capacity is not None:
        command = [str(PYTHON), str(ROOT / "filtered_receiver.py"),
                   "--destination", str(destination),
                   "--reported-free-gib", str(filtered_capacity),
                   "--space-check-path", str(space_guard or ROOT)]
        if udid:
            command.extend(["--udid", udid])
        if include_related:
            command.extend(["--include-related", "--related-inventory", str(related_inventory)])
        if media_inventory is not None:
            command.extend(["--media-inventory", str(media_inventory)])
        return command
    command = [str(PYTHON), "-m", "pymobiledevice3", "backup2", "backup",
               "--only", "whatsapp", "--only-regex", RELATED_PATTERN if include_related else JOURNAL_PATTERN,
               "--no-patch-manifest"]
    if udid:
        command.extend(["--udid", udid])
    command.append(str(destination))
    return command


def stop_capture(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="Start the filtered capture")
    parser.add_argument("--destination", type=Path, help="New, separate capture folder")
    parser.add_argument("--udid", help="Select a device when multiple phones are connected")
    parser.add_argument("--include-related", action="store_true",
                        help="Also retain WhatsApp search indexes, other databases, preferences and logs, excluding media")
    parser.add_argument("--related-inventory", type=Path,
                        help="WhatsApp file inventory used to select exact backup payload identifiers")
    parser.add_argument("--media-inventory", type=Path,
                        help="Also retain a small explicit list of verified WhatsApp media files; requires --include-related")
    parser.add_argument("--space-check-path", type=Path,
                        help="Also monitor real free space on this backing filesystem (for sparse disk images)")
    parser.add_argument("--filtered-capacity", type=int, choices=(40,),
                        help="For this filtered capture only, report 40 GiB for the discarded full stream; real disk space remains monitored")
    args = parser.parse_args()
    selected = {}
    inventory_path = None
    if args.media_inventory and not args.include_related:
        parser.error("Explicit media capture requires --include-related and its verified receiver.")
    media_inventory = args.media_inventory.expanduser().resolve(strict=True) if args.media_inventory else None
    if args.include_related:
        inventory_path = args.related_inventory
        if inventory_path is None or args.filtered_capacity is None:
            parser.error("Related capture requires a completed file inventory and --filtered-capacity 40.")
        inventory_path = inventory_path.expanduser().resolve(strict=True)
        inventory_report, selected = load_related_inventory(inventory_path, media_inventory)
        inventory_device = Path(inventory_report["source_backup"]).name
        if args.udid and args.udid != inventory_device:
            parser.error("The inventory belongs to a different iPhone.")
        args.udid = inventory_device
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ")
    destination = (args.destination or ROOT / "captures" / stamp).expanduser().resolve()
    space_guard = args.space_check_path.expanduser().resolve() if args.space_check_path else None
    if args.filtered_capacity is not None and space_guard is None:
        space_guard = ROOT
    command = command_for(destination, args.udid, args.filtered_capacity, space_guard, args.include_related, inventory_path, media_inventory)
    print("Operation: backup2 backup with WhatsApp-only payload retention", flush=True)
    print("Destination:", destination, flush=True)
    print("Other app payloads are not saved; backup metadata is retained.", flush=True)
    print("This is a partial extraction for examination, not a full restore backup.", flush=True)
    if args.filtered_capacity is not None:
        print("The receiver reports 40 GiB to the full-stream pre-check; real physical space is still limited by the 1.5 GiB guard.", flush=True)
    if not args.run:
        print("Plan only. Add --run to start. No device connection attempted.")
        return 0
    try:
        from importlib.metadata import version
        if version("pymobiledevice3") != "11.34.1":
            raise ValueError("Install the pinned capture dependencies before a live capture.")
    except (ImportError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if destination.exists():
        print("Destination already exists; use a fresh folder.", file=sys.stderr)
        return 2
    ancestor = destination.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if space_guard and not space_guard.exists():
        print("Backing filesystem guard path does not exist.", file=sys.stderr)
        return 2
    monitored_paths = (ancestor, space_guard) if space_guard else (ancestor,)
    if min(shutil.disk_usage(str(path)).free for path in monitored_paths) < MIN_FREE_BYTES:
        print("Less than 1.5 GiB available; capture was not started.", file=sys.stderr)
        return 2
    # This destination must not overlap Apple's standard backup folder, even
    # when that location is redirected by a symbolic link.
    standard = (Path.home() / "Library/Application Support/MobileSync/Backup").resolve()
    if destination == standard or standard in destination.parents or destination in standard.parents:
        print("Refusing to write into Apple's existing backup location.", file=sys.stderr)
        return 2
    previous_umask = os.umask(0o077)
    process = None
    state = {"operation": "filtered WhatsApp capture", "status": "starting",
             "started_utc": datetime.now(timezone.utc).isoformat(),
             "minimum_free_bytes": MIN_FREE_BYTES, "full_device_restore_supported": False,
             "filtered_capacity_gib": args.filtered_capacity,
             "include_related": args.include_related,
             "related_inventory": str(inventory_path) if inventory_path else None,
             "media_inventory": str(media_inventory) if media_inventory else None,
             "physical_space_guard": str(space_guard) if space_guard else None}
    try:
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
        marker = destination / "PARTIAL_EXTRACTION_NOT_FOR_DEVICE_RESTORE.txt"
        marker.write_text("WhatsApp database payloads and backup metadata only.\n"
                          "Other app files are intentionally absent. Do not restore this extraction to an iPhone.\n"
                          "It does not establish that deleted messages were recovered.\n", encoding="utf-8")
        with (destination / "capture.log").open("xb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            state["status"] = "running"
            next_report = 0.0
            while process.poll() is None:
                monitored_paths = (destination, space_guard) if space_guard else (destination,)
                free = min(shutil.disk_usage(str(path)).free for path in monitored_paths)
                if free < MIN_FREE_BYTES:
                    state["status"] = "stopped_low_disk_space"
                    print("Stopping capture to preserve 1.5 GiB of free space.", flush=True)
                    stop_capture(process)
                    break
                now = time.monotonic()
                if now >= next_report:
                    print("Capture running; Mac free space: %.2f GiB. Details: %s" %
                          (free / (1024**3), destination / "capture.log"), flush=True)
                    next_report = now + 30
                time.sleep(1)
        state["exit_code"] = process.wait()
        if state["status"] == "running":
            state["status"] = "stream_completed" if state["exit_code"] == 0 else "capture_failed"
        if state["status"] == "stream_completed" and selected:
            device_directory = destination / args.udid
            missing = []
            present = 0
            for file_id, entry in selected.items():
                payload = device_directory / file_id[:2] / file_id
                if not payload.is_file():
                    payload = device_directory / file_id
                if payload.is_file():
                    present += 1
                elif entry.get("declared_bytes", 0):
                    missing.append(entry["relative_path"])
            state["related_targets_expected"] = len(selected)
            state["related_targets_present"] = present
            state["related_nonempty_targets_missing"] = missing
            if missing:
                state["status"] = "capture_missing_related_files"
        print("Capture status:", state["status"], flush=True)
        print("No phone restore or erase operation was requested.", flush=True)
        if state["status"] == "stopped_low_disk_space":
            return 3
        return state["exit_code"] if state["status"] == "stream_completed" else (state["exit_code"] or 2)
    except KeyboardInterrupt:
        state["status"] = "interrupted"
        if process:
            stop_capture(process)
        return 130
    except (OSError, ValueError) as error:
        state["status"] = "capture_failed"
        state["error"] = str(error)
        if process:
            stop_capture(process)
        print("Capture stopped:", error, file=sys.stderr)
        return 2
    finally:
        if destination.is_dir():
            state["finished_utc"] = datetime.now(timezone.utc).isoformat()
            report = destination / "capture-state.json"
            with report.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
                stream.write("\n")
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
