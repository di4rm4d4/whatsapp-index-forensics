#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Backend for the space-guarded, WhatsApp-only receiver.

The iPhone checks space for its entire outgoing stream even though the host
discards other apps' payloads. This process advertises 40 GiB for that check.
That is logical capacity, NOT real free storage. The parent capture process
must keep monitoring real physical space and stop below its 1.5 GiB reserve.
This backend also checks real space each time the device asks for capacity.

The only CLI invocation constructed here is filtered `backup2 backup`.
Neither the dependency's installed files nor its normal CLI are modified.
The result is for examination only and must never be restored to a phone.
"""

import argparse
from importlib.metadata import version
from pathlib import Path
import runpy
import shutil
import sys

from related_data_rules import RELATED_PATTERN, load_related_inventory


MIN_FREE_BYTES = 1536 * 1024 * 1024


def manifest_file_filter(original, selected):
    """Match backup payload identifiers even when device paths omit a domain."""
    logged = set()

    def preserve(file_name, device_name, callback):
        file_id = Path(file_name).name.lower()
        if file_id in selected:
            if file_id not in logged:
                print("Retaining indexed WhatsApp file: " + selected[file_id]["relative_path"], flush=True)
                logged.add(file_id)
            return True
        return original(file_name, device_name, callback)

    return preserve


def capacity_handler(destination, physical_guard, logical_capacity):
    destination = destination.resolve()
    physical_guard = physical_guard.resolve()

    async def report_capacity(link, _message):
        if link.root_path.resolve() != destination or link.preserve_file is None:
            raise RuntimeError("Logical capacity is restricted to this filtered extraction destination.")
        actual = min(shutil.disk_usage(str(destination)).free,
                     shutil.disk_usage(str(physical_guard)).free)
        reported = logical_capacity if actual >= MIN_FREE_BYTES else actual
        link._reported_free_space = reported
        print("Filtered stream check: actual free %.2f GiB; reported %.2f GiB. "
              "Other app payloads are discarded; real-space guard remains active." %
              (actual / 1024**3, reported / 1024**3), flush=True)
        await link.status_response(0, status_dict=reported)

    return report_capacity


def receive_guard(original_receive, destination, physical_guard):
    destination = destination.resolve()
    physical_guard = physical_guard.resolve()

    async def receive(link, size):
        if link.root_path.resolve() != destination or link.preserve_file is None:
            raise RuntimeError("The filtered receiver cannot operate outside its extraction destination.")
        actual = min(shutil.disk_usage(str(destination)).free,
                     shutil.disk_usage(str(physical_guard)).free)
        if actual - size < MIN_FREE_BYTES:
            raise RuntimeError("Stopping before receiving another block to preserve 1.5 GiB of real free space.")
        return await original_receive(link, size)

    return receive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--reported-free-gib", required=True, type=int, choices=(40,))
    parser.add_argument("--space-check-path", required=True, type=Path)
    parser.add_argument("--udid")
    parser.add_argument("--include-related", action="store_true")
    parser.add_argument("--related-inventory", type=Path)
    parser.add_argument("--media-inventory", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve(strict=True)
    guard = args.space_check_path.resolve(strict=True)
    if not (destination / "PARTIAL_EXTRACTION_NOT_FOR_DEVICE_RESTORE.txt").is_file():
        raise RuntimeError("Run this backend through capture_whatsapp.py so real-space monitoring remains active.")
    if version("pymobiledevice3") != "11.34.1":
        raise RuntimeError("This backend was verified with pymobiledevice3 11.34.1 only.")
    from pymobiledevice3.services.device_link import DeviceLink
    if args.include_related:
        if args.related_inventory is None:
            raise RuntimeError("The broader capture requires the verified WhatsApp inventory.")
        _report, selected = load_related_inventory(args.related_inventory.resolve(strict=True),
                                                 args.media_inventory.resolve(strict=True) if args.media_inventory else None)
        from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
        Mobilebackup2Service.should_preserve_backup_file = staticmethod(
            manifest_file_filter(Mobilebackup2Service.should_preserve_backup_file, selected))
    DeviceLink.get_free_disk_space = capacity_handler(destination, guard, args.reported_free_gib * 1024**3)
    DeviceLink._recvall = receive_guard(DeviceLink._recvall, destination, guard)
    cli = ["pymobiledevice3", "backup2", "backup", "--only", "whatsapp",
           "--only-regex", RELATED_PATTERN if args.include_related else r"(?i)whatsapp.*ChatStorage\.sqlite-journal$",
           "--no-patch-manifest"]
    if args.udid:
        cli.extend(["--udid", args.udid])
    cli.append(str(destination))
    sys.argv = cli
    runpy.run_module("pymobiledevice3", run_name="__main__")


if __name__ == "__main__":
    main()
