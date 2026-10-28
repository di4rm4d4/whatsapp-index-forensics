#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Export index-history term sets to a local, escaped HTML report.

There is no automatic contact attribution or sentence reconstruction.
"""

import argparse
import html
import json
import os
from pathlib import Path
import sys

from forensic_io import digest, separate_output


def render(report_path, destination, body_column="0", absent_only=False):
    report_path = Path(report_path).expanduser().resolve(strict=True)
    destination = separate_output(report_path, destination)
    report_hash = digest(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("source_unchanged") is not True or report.get("errors") or report.get("segment_errors"):
        raise ValueError("Use a source-verified history report without decoding errors.")
    cards = []
    for record in report["documents"]:
        present = record.get("present_in_current_content", record.get("present_in_current_content_or_docsize"))
        if present is not None and type(present) is not bool:
            raise ValueError("Invalid current-content presence value.")
        if absent_only and present is not False:
            continue
        terms = sorted({term for item in record["columns"].get(str(body_column), []) for term in item["terms"]})
        reference = "Segment %s · document %s" % (record["segment_id"], record["doc_id"])
        state = "unknown" if present is None else str(present).lower()
        cards.append('<article><h2>%s</h2><p>Present in current content: %s</p><p class="terms">%s</p></article>' % (
            html.escape(reference), state, html.escape(" · ".join(terms) or "No terms in this column")))
    if digest(report_path) != report_hash:
        raise ValueError("The input report changed while it was being read.")
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Historical index terms</title><style>
body{max-width:850px;margin:40px auto;padding:0 20px;font:16px/1.6 system-ui,sans-serif;color:#1f2937;background:#fafaf7}
h1{font:36px Georgia,serif}h2{font-size:17px}article{padding:12px 20px;margin:16px 0;border:1px solid #ccd3ce;background:white}
.notice{padding:16px;background:#fff3d5}.terms{overflow-wrap:anywhere}small{overflow-wrap:anywhere}
</style><h1>Historical index terms</h1><p class="notice">These are unordered, potentially normalized terms.
They are not original sentences, verified senders, exact dates, or a restored conversation.
Absence from current content alone does not prove deletion. Segment versions stay separate.</p>
<p>Report SHA-256: <small>__HASH__</small></p>__CARDS__</html>"""
    page = page.replace("__HASH__", report_hash).replace("__CARDS__", "\n".join(cards))
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(page)
    print("Term sets exported:", len(cards))
    print("Output:", destination)
    return len(cards)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--body-column", default="0")
    parser.add_argument("--absent-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        render(args.report, args.destination, args.body_column, args.absent_only)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Export stopped:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
