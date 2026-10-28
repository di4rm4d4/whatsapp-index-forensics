#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a separate search database from an index-history report.

Every segment/document version remains a distinct row. Sorted term sets are
indexed for discovery only; they are never presented as original sentences.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys

from forensic_io import digest, separate_output


def build(report_path, destination, body_column="0", absent_only=False):
    report_path = Path(report_path).expanduser().resolve(strict=True)
    destination = separate_output(report_path, destination)
    report_hash = digest(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("source_unchanged") is not True:
        raise ValueError("The history report does not confirm an unchanged source.")
    if report.get("errors") or report.get("segment_errors"):
        raise ValueError("Resolve decoding errors before building a search index.")
    rows, seen = [], set()
    for record in report["documents"]:
        identity = (str(record["segment_id"]), record["doc_id"])
        if type(identity[1]) is not int or identity in seen:
            raise ValueError("Invalid or duplicate segment/document identity.")
        seen.add(identity)
        present = record.get("present_in_current_content", record.get("present_in_current_content_or_docsize"))
        if present is not None and type(present) is not bool:
            raise ValueError("Invalid current-content presence value.")
        if absent_only and present is not False:
            continue
        columns = record["columns"]
        if not isinstance(columns, dict):
            raise ValueError("Invalid column map.")
        body_positions = columns.get(str(body_column), [])
        terms = set()
        for position in body_positions:
            for term in position["terms"]:
                if not isinstance(term, str):
                    raise ValueError("Index terms must be strings.")
                terms.add(term)
        rows.append((identity, present, sorted(terms), columns))
    if not rows:
        raise ValueError("No document versions match this selection.")
    if not any(row[2] for row in rows):
        raise ValueError("The selected body column contains no terms.")
    if digest(report_path) != report_hash:
        raise ValueError("The history report changed while it was being read.")
    # Reserve a fresh file without clobbering a previous analysis.
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.close(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    connection = sqlite3.connect(destination)
    try:
        connection.executescript("""
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE entries(
                id INTEGER PRIMARY KEY, segment_id TEXT NOT NULL, doc_id INTEGER NOT NULL,
                present_in_current_content INTEGER, terms_json TEXT NOT NULL,
                columns_json TEXT NOT NULL, UNIQUE(segment_id, doc_id)
            );
            CREATE VIRTUAL TABLE term_search USING fts5(terms);
        """)
        metadata = {
            "format_version": "1", "created_utc": datetime.now(timezone.utc).isoformat(),
            "input_report_sha256": report_hash,
            "reported_source_sha256": str(report.get("source_sha256", "unknown")),
            "body_column": str(body_column), "absent_only": json.dumps(absent_only),
            "interpretation": "Unordered normalized index terms, not verbatim messages. Versions and dates are not conversation chronology.",
        }
        connection.executemany("INSERT INTO metadata VALUES (?,?)", metadata.items())
        for number, (identity, present, terms, columns) in enumerate(rows, 1):
            connection.execute("INSERT INTO entries VALUES (?,?,?,?,?,?)", (
                number, *identity, present, json.dumps(terms, ensure_ascii=False),
                json.dumps(columns, ensure_ascii=False),
            ))
            connection.execute("INSERT INTO term_search(rowid,terms) VALUES (?,?)", (number, " ".join(terms)))
        connection.commit()
    finally:
        connection.close()
    print("Document versions indexed:", len(rows))
    print("Output:", destination)
    print("Search contains unordered terms, not restored messages.")
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--body-column", default="0", help="Numeric FTS3/4 column or FTS5 name such as c0")
    parser.add_argument("--absent-only", action="store_true", help="Include only rows confirmed absent from current content")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        build(args.report, args.destination, args.body_column, args.absent_only)
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        print("Re-indexing stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
