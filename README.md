# WhatsApp Index Forensics

Python tools for preserving WhatsApp files from local iPhone backups, examining
historical SQLite search segments, and building a **separate searchable index
of retained terms**.

The original investigation found older FTS4 entries that normal search no longer
returned. This repository makes the reusable tooling available with generated
examples. It contains no device backups, personal messages, identifiers, or
case-specific sentence reconstructions.

**A search-index remnant is not a restored message.** Terms may be normalized,
deduplicated, or unordered. A row absent from current content is a candidate
remnant; its sender, date, original wording, and reason for absence require
additional evidence. Re-indexing here creates an analysis database; it does not
rebuild or modify WhatsApp's own index.

## Try it without a phone

Python 3.10+ with SQLite FTS3/4 and FTS5 support is enough for the analysis tools.
The normal Python distribution includes these extensions on many platforms;
the test suite checks the required functionality.

```sh
python3 examples/make_demo.py local/demo/input/synthetic.sqlite
python3 inspect_database.py local/demo/input/synthetic.sqlite local/demo/inventory
python3 fts34_history.py local/demo/input/synthetic.sqlite docs local/demo/history
python3 reindex.py local/demo/history/index-history.json local/demo/search.sqlite --absent-only
python3 search_index.py local/demo/search.sqlite lantern
python3 export_terms.py local/demo/history/index-history.json local/demo/terms.html --absent-only
```

The demo inserts synthetic terms, commits them, then deletes one row. Normal
FTS search no longer returns that row. The historical parser can still find its
older segment in this generated example:

```json
{
  "segment_id": "0:0",
  "doc_id": 42,
  "present_in_current_content": false,
  "retained_terms_unordered": ["blue", "lantern", "meeting"]
}
```

The example demonstrates one retention pattern, not a promise that deleted
entries survive in another database. Reuse fresh output paths for another run.

## Tools

| Script | Purpose |
| --- | --- |
| `capture_whatsapp.py` | Plan or run a filtered local-backup capture with a physical disk-space reserve. |
| `filtered_receiver.py` | Version-pinned receiver for an explicit manifest inventory and optional logical-capacity handling. |
| `decrypt_whatsapp.py` | Unlock a completed backup locally, inventory WhatsApp paths, or export selected payloads with hashes. |
| `inspect_backup.py` | List standard Mac backups or copy raw chat files from an unencrypted manifest. |
| `inspect_database.py` | Inventory SQLite schemas, integrity status, and row counts on disposable copies. |
| `fts34_history.py` | Parse historical FTS3/4 leaves, retaining each segment/document version separately. |
| `fts5_history.py` | Experimental FTS5 segment inspection through disposable reconstructions. |
| `reindex.py` | Build a fresh FTS5 analysis database from an error-free history report. |
| `search_index.py` | Search literal words and return unordered terms with their version references. |
| `export_terms.py` | Produce an escaped, offline HTML report of retained term sets. |

Use `python3 SCRIPT.py --help` for arguments. The analysis scripts use only the
standard library. Optional backup/decryption dependencies are separate.

## Work on a preserved database

Supply a completed, stable extraction, with any captured `-wal`, `-shm` and
`-journal` files beside the database under their original names. The tools hash
the input files, make verified temporary copies, query those copies, and check
the source hashes again. They include captured WAL data in the analysis.

```sh
python3 inspect_database.py /path/to/search.sqlite local/inventory
python3 fts34_history.py /path/to/search.sqlite TABLE_NAME local/history
python3 reindex.py local/history/index-history.json local/search.sqlite --body-column 0
python3 search_index.py local/search.sqlite meeting lantern
```

Determine the table and body column from the schema. `docs` and column `0`
matched the original FTS4 investigation, but other versions may differ.
Multiple search words are combined with AND. The search database indexes
alphabetically sorted term sets, so it cannot answer questions about original
phrase order. Every historical version remains a separate row.

For the experimental FTS5 probe:

```sh
python3 fts5_history.py /path/to/search.sqlite TABLE_NAME local/fts5-history
python3 reindex.py local/fts5-history/index-history.json local/fts5-search.sqlite --body-column c0
```

FTS5 internals vary. Contentless-delete indexes are rejected. Decode failures
produce a nonzero exit and prevent the standard re-index/export commands from
accepting the report. See [interpretation and limits](docs/interpretation.md).

## Local iPhone backup workflow

For a device and backup you own or have explicit permission to examine, see
[capture and extraction](docs/capture-and-extraction.md). The optional capture
path uses `pymobiledevice3==11.34.1`; the dependency versions match the recovered
implementation. Install them in a Python 3.12 virtual environment:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-capture.txt
```

The live capture requires the device's normal trust/unlock approvals, and
encrypted backups require their existing local-backup password. Password input
is hidden and stays local. A filtered capture is an **analysis extraction**, not
a full-device restore backup.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

Tests generate their own databases and manifests. They cover historical FTS3/4
entries, updates, descending identifiers, multiple leaf pages, contentless
presence reporting, WAL handling, FTS5 inspection, re-indexing, escaped HTML,
source hash changes, path traversal, and capture planning without a device.

The public release's tests do not perform a fresh live-device capture or
decrypt a real encrypted backup. The original capture/decryption flow was used
in the October 2026 investigation; current device compatibility needs separate
verification. See [release scope](docs/release-scope.md).

## Development and attribution

Developed by Diana McDermott. The extraction and segment-analysis scripts were
adapted from the original recovery work; reusable re-indexing, search, synthetic
fixtures, and regression checks were added for this release.

Contributions should use generated data. Please do not submit personal backups,
message exports, phone numbers, account identifiers, or credentials in issues.

Source: **GPL-3.0-or-later**. See [LICENSE](LICENSE) and
[third-party notices](THIRD_PARTY_NOTICES.md). No WhatsApp or Apple affiliation.
