#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read separate FTS3/4 segment versions from a preserved SQLite database.

Output is indexed terms and positions, not a recovered conversation. A row
missing from current content is a candidate remnant, not proof of deletion.
See https://sqlite.org/fts3.html#_data_structures for the on-disk format.
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

from forensic_io import quote, separate_output, snapshot, write_json


def integer(data, offset):
    """FTS3/4 unsigned 64-bit varint (least-significant group first)."""
    if offset < 0:
        raise ValueError("Negative FTS integer offset.")
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("Truncated FTS integer.")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("Oversized FTS integer.")
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, offset
    raise ValueError("Oversized FTS integer.")


def leaf_tokens(data, descending=False):
    height, offset = integer(data, 0)
    if height != 0:
        raise ValueError("Expected an FTS leaf node.")
    previous = b""
    first_term = True
    while offset < len(data):
        prefix = 0
        if not first_term:
            prefix, offset = integer(data, offset)
        length, offset = integer(data, offset)
        if prefix > len(previous) or length > len(data) - offset:
            raise ValueError("Invalid term prefix or length.")
        term = previous[:prefix] + data[offset:offset + length]
        offset += length
        size, offset = integer(data, offset)
        if size > len(data) - offset:
            raise ValueError("Invalid document-list size.")
        doclist = data[offset:offset + size]
        offset += size
        previous = term
        first_term = False
        pos, docid, first_doc = 0, 0, True
        while pos < len(doclist):
            delta, pos = integer(doclist, pos)
            if first_doc:
                docid = delta - 2**64 if delta >= 2**63 else delta
                first_doc = False
            else:
                docid += -delta if descending else delta
            column, token_position = 0, 0
            while True:
                value, pos = integer(doclist, pos)
                if value == 0:
                    break
                if value == 1:
                    column, pos = integer(doclist, pos)
                    token_position = 0
                else:
                    token_position += value - 2
                    yield term.decode("utf-8", "replace"), docid, column, token_position


def examine(database, table, destination):
    database = Path(database).expanduser()
    if database.is_symlink():
        raise ValueError("Symbolic-link databases are not accepted.")
    database = database.resolve(strict=True)
    destination = separate_output(database, destination)
    if destination.exists():
        raise ValueError("Use a fresh output directory.")
    report = {
        "format_version": 1, "source_database": str(database), "table": table,
        "segments": [], "documents": [], "errors": [],
        "interpretation": "Historical index terms and positions. Wording, attribution, dates and deletion status require separate evidence.",
        "limitations": [
            "Segment versions are kept separate; they are not a conversation chronology.",
            "Terms may be normalized, deduplicated or unordered by the application before indexing.",
            "A missing current row alone does not establish a deleted message.",
            "Prefix indexes and language indexes may produce additional segment versions.",
        ],
    }
    with snapshot(database) as (connection, hashes):
        report["source_files"] = hashes
        report["source_sha256"] = hashes[database.name]["sha256"]
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()
        if not schema or not schema[0] or not re.search(r"\bfts[34]\s*\(", schema[0], re.I):
            raise ValueError("The selected table is not FTS3/4.")
        descending = bool(re.search(r"\border\s*=\s*['\"]?desc\b", schema[0], re.I))
        names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        current = None
        if table + "_content" in names:
            current = {r[0] for r in connection.execute("SELECT docid FROM " + quote(table + "_content"))}
        report["current_content_available"] = current is not None
        segments = connection.execute(
            "SELECT level,idx,start_block,leaves_end_block,root FROM " + quote(table + "_segdir") + " ORDER BY level,idx"
        ).fetchall()
        for level, index, start, end, root in segments:
            segment_id = str(level) + ":" + str(index)
            report["segments"].append({"id": segment_id, "first_leaf": start, "last_leaf": end})
            if start == 0:
                leaves = [("root", root)]
            else:
                leaves = connection.execute(
                    "SELECT blockid,block FROM " + quote(table + "_segments") +
                    " WHERE blockid BETWEEN ? AND ? ORDER BY blockid", (start, end)
                ).fetchall()
                if len(leaves) != end - start + 1:
                    report["errors"].append({"segment": segment_id, "error": "Missing segment leaf blocks."})
            documents = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
            for leaf_id, leaf in leaves:
                try:
                    for term, docid, column, position in leaf_tokens(leaf, descending):
                        documents[docid][column][position].add(term)
                except (ValueError, TypeError) as error:
                    report["errors"].append({"segment": segment_id, "leaf": leaf_id, "error": str(error)})
            for docid, columns in sorted(documents.items()):
                recovered = {
                    "segment_id": segment_id, "doc_id": docid,
                    "present_in_current_content": docid in current if current is not None else None,
                    "columns": {},
                }
                for column, positions in sorted(columns.items()):
                    recovered["columns"][str(column)] = [
                        {"position": position, "terms": sorted(positions[position])}
                        for position in sorted(positions)
                    ]
                report["documents"].append(recovered)
    report["source_unchanged"] = True  # snapshot verifies this before returning.
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_json(destination / "index-history.json", report)
    print("Segments:", len(report["segments"]))
    print("Document versions with terms:", len(report["documents"]))
    print("Versions absent from current content:", sum(r["present_in_current_content"] is False for r in report["documents"]))
    print("Decoding errors:", len(report["errors"]))
    print("Original database and sidecars unchanged: True")
    print("Output:", destination)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("table")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = examine(args.database, args.table, args.destination)
        return 4 if report["errors"] else 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print("Analysis stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
