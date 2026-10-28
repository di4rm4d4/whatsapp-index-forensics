#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Search retained term sets using literal words, with every version separate."""

import argparse
import json
from pathlib import Path
import re
import sqlite3
import sys

from forensic_io import snapshot


def search(database, words, limit=20):
    tokens = re.findall(r"\w+", " ".join(words), flags=re.UNICODE)
    if not tokens:
        raise ValueError("Supply at least one word.")
    if not 1 <= limit <= 1000:
        raise ValueError("Limit must be between 1 and 1000.")
    query = " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)
    with snapshot(database) as (connection, _hashes):
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if metadata.get("format_version") != "1":
            raise ValueError("Unrecognized search database format.")
        rows = connection.execute("""
            SELECT e.segment_id,e.doc_id,e.present_in_current_content,e.terms_json
            FROM term_search JOIN entries e ON e.id=term_search.rowid
            WHERE term_search MATCH ? ORDER BY e.id LIMIT ?
        """, (query, limit)).fetchall()
        return [
            {"segment_id": segment, "doc_id": docid,
             "present_in_current_content": bool(present) if present is not None else None,
             "retained_terms_unordered": json.loads(terms)}
            for segment, docid, present, terms in rows
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("words", nargs="+")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    try:
        print(json.dumps({"interpretation": "Unordered search terms, not original messages.",
                          "matches": search(args.database, args.words, args.limit)}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print("Search stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
