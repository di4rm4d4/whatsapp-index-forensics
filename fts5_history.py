#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read historical FTS5 segment tokens without modifying the input database.

This examines each segment independently in a disposable reconstruction.
Old index entries may contain words for a deleted document even when normal
search suppresses them. Results are index tokens with positions, not verbatim
messages: punctuation/capitalization may be lost, versions may differ, and
contact attribution requires separate evidence.

Format reference: https://sqlite.org/fts5.html#fts5_data_structures
"""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import sys

from forensic_io import separate_output, snapshot, write_json


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def varint(data, offset):
    value = 0
    for _ in range(8):
        if offset >= len(data):
            raise ValueError("Truncated index integer.")
        byte = data[offset]
        offset += 1
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, offset
    if offset >= len(data):
        raise ValueError("Truncated index integer.")
    return (value << 8) | data[offset], offset + 1


def encode_varint(number):
    if not 0 <= number < 2**56:
        raise ValueError("Unsupported structure integer size.")
    result = [number & 127]
    number >>= 7
    while number:
        result.append((number & 127) | 128)
        number >>= 7
    return bytes(reversed(result))


def parse_segments(blob, contentless_delete=False):
    offset = 4
    levels, offset = varint(blob, offset)
    total, offset = varint(blob, offset)
    _written, offset = varint(blob, offset)
    if levels > 100 or total > 10000:
        raise ValueError("Unexpected index structure size.")
    result = []
    for level in range(levels):
        _merge, offset = varint(blob, offset)
        count, offset = varint(blob, offset)
        for _ in range(count):
            segid, offset = varint(blob, offset)
            first, offset = varint(blob, offset)
            last, offset = varint(blob, offset)
            result.append({"id": segid, "first": first, "last": last, "level": level})
            if contentless_delete:
                for _ in range(5):
                    _value, offset = varint(blob, offset)
    if len(result) != total or offset != len(blob):
        raise ValueError("Index structure format needs further inspection.")
    return result


def examine(database, table, destination):
    database = database.expanduser()
    if database.is_symlink():
        raise ValueError("Symbolic-link databases are not accepted.")
    database = database.resolve(strict=True)
    destination = separate_output(database, destination)
    if destination.exists():
        raise ValueError("Use a fresh output directory.")
    with snapshot(database) as (source, source_hashes):
        source_hash = source_hashes[database.name]["sha256"]
        row = source.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()
        if not row or not re.search(r"\bfts5\s*\(", row[0], re.I):
            raise ValueError("The selected table is not FTS5.")
        schema = row[0]
        data = source.execute("SELECT id,block FROM " + quote(table + "_data")).fetchall()
        index = source.execute("SELECT segid,term,pgno FROM " + quote(table + "_idx")).fetchall()
        blocks = dict(data)
        structure = blocks[10]
        averages = blocks.get(1, b"")
        offset = 0
        vector = []
        while offset < len(averages):
            value, offset = varint(averages, offset)
            vector.append(value)
        columns = len(vector) - 1
        if not 1 <= columns <= 128:
            raise ValueError("Could not establish the index column count.")
        detail_match = re.search(r"\bdetail\s*=\s*['\"]?(full|col|none)", schema, re.I)
        detail = detail_match.group(1).lower() if detail_match else "full"
        contentless_delete = bool(re.search(r"\bcontentless_delete\s*=\s*['\"]?1", schema, re.I))
        if contentless_delete:
            raise ValueError("FTS5 contentless_delete indexes are not supported by this probe.")
        segments = parse_segments(structure, contentless_delete)
        names = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        current_ids = None
        if table + "_content" in names:
            current_ids = {r[0] for r in source.execute("SELECT id FROM " + quote(table + "_content"))}
        elif table + "_docsize" in names:
            current_ids = {r[0] for r in source.execute("SELECT id FROM " + quote(table + "_docsize"))}
    report = {"source_database": str(database), "source_sha256": source_hash,
              "table": table, "columns": columns, "detail": detail,
              "segments": segments, "documents": [], "segment_errors": [],
              "interpretation": "Historical search tokens; not verbatim messages or established contact attribution."}
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    report["source_files"] = source_hashes
    with tempfile.TemporaryDirectory(prefix="segment-work-", dir=destination) as temp:
        for segment in segments:
            if not 0 < segment["first"] <= segment["last"]:
                continue
            file = Path(temp) / ("segment-" + str(segment["id"]) + ".sqlite")
            connection = sqlite3.connect(file)
            try:
                column_list = ','.join('c' + str(i) for i in range(columns))
                connection.execute('CREATE VIRTUAL TABLE scan USING fts5(' + column_list + ',content="",columnsize=0,detail=' + detail + ')')
                connection.execute('DELETE FROM scan_data')
                connection.executemany('INSERT INTO scan_data VALUES (?,?)', data)
                connection.execute('DELETE FROM scan_idx')
                connection.executemany('INSERT INTO scan_idx VALUES (?,?,?)', index)
                selected = structure[:4] + b''.join(encode_varint(v) for v in (
                    1, 1, 0, 0, 1, segment["id"], segment["first"], segment["last"]))
                connection.execute('UPDATE scan_data SET block=? WHERE id=10', (selected,))
                connection.commit()
                connection.close()
                connection = sqlite3.connect(file)
                connection.execute("CREATE VIRTUAL TABLE temp.vocabulary USING fts5vocab(main,scan,instance)")
                documents = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
                for term, docid, column, position in connection.execute('SELECT term,doc,col,offset FROM vocabulary'):
                    documents[docid][column][position].add(term)
                for docid, values in documents.items():
                    recovered = {"segment_id": segment["id"], "doc_id": docid,
                                 "present_in_current_content_or_docsize": docid in current_ids if current_ids is not None else None,
                                 "columns": {}}
                    for column, positions in values.items():
                        ordered = sorted(positions, key=lambda value: -1 if value is None else value)
                        recovered["columns"][str(column)] = [
                            {"position": position, "terms": sorted(positions[position])}
                            for position in ordered]
                    report["documents"].append(recovered)
            except (sqlite3.Error, ValueError) as error:
                report["segment_errors"].append({"segment_id": segment["id"], "error": str(error)})
            finally:
                connection.close()
    report["source_unchanged"] = True
    write_json(destination / "index-history.json", report)
    print("Historical index segments examined:", len(segments))
    print("Document versions with tokens:", len(report["documents"]))
    print("Versions absent from current content/docsize:", sum(r["present_in_current_content_or_docsize"] is False for r in report["documents"]))
    print("Segment errors:", len(report["segment_errors"]))
    print("Input database unchanged:", report["source_unchanged"])
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
        return 4 if report["segment_errors"] else 0
    except (OSError, ValueError, KeyError, sqlite3.Error) as error:
        print("Analysis stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
