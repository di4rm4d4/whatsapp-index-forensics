#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory table schemas and row counts using a verified disposable copy."""

import argparse
import os
from pathlib import Path
import sqlite3
import sys

from forensic_io import quote, separate_output, snapshot, write_json


def inspect(database, destination):
    database = Path(database).expanduser()
    if database.is_symlink():
        raise ValueError("Symbolic-link databases are not accepted.")
    database = database.resolve(strict=True)
    destination = separate_output(database, destination)
    if destination.exists():
        raise ValueError("Use a fresh output directory.")
    report = {"source_database": str(database), "tables": []}
    with snapshot(database) as (connection, hashes):
        report["source_files"] = hashes
        report["quick_check"] = [r[0] for r in connection.execute("PRAGMA quick_check")]
        for name, schema in connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall():
            table = {"name": name, "schema": schema}
            report["tables"].append(table)
            try:
                table["rows"] = connection.execute("SELECT count(*) FROM " + quote(name)).fetchone()[0]
            except sqlite3.Error as error:
                table["count_error"] = str(error)
    report["source_unchanged"] = True
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_json(destination / "database-inventory.json", report)
    print("Tables inventoried:", len(report["tables"]))
    print("Original database and sidecars unchanged: True")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        inspect(args.database, args.destination)
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print("Inspection stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
