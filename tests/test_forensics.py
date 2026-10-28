# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks use generated data only; no phone or private files."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import capture_whatsapp
import decrypt_whatsapp
import export_terms
import forensic_io
import fts34_history
import fts5_history
import inspect_backup
import inspect_database
import reindex
import related_data_rules
import search_index
from examples.make_demo import make


def encode(number):
    number &= (1 << 64) - 1
    result = []
    while number >= 128:
        result.append((number & 127) | 128)
        number >>= 7
    return bytes(result + [number])


class Varints(unittest.TestCase):
    def test_fts34_round_trips(self):
        for value in (0, 1, 127, 128, 255, 2**32, 2**63, 2**64 - 1):
            data = encode(value)
            self.assertEqual(fts34_history.integer(data, 0), (value, len(data)))

    def test_truncated_fts34(self):
        for data in (b"", b"\x80", b"\x80\x80"):
            with self.assertRaises(ValueError):
                fts34_history.integer(data, 0)

    def test_oversized_fts34(self):
        with self.assertRaises(ValueError):
            fts34_history.integer(b"\xff" * 10, 0)

    def test_negative_offset(self):
        with self.assertRaises(ValueError):
            fts34_history.integer(b"\x00", -1)

    def test_invalid_leaf(self):
        for data in (b"\x01", b"\x00\x05ab", b"\x00\x01a\x05a"):
            with self.assertRaises(ValueError):
                list(fts34_history.leaf_tokens(data))

    def test_signed_document_id(self):
        docs = encode(-2) + encode(2) + b"\x00"
        data = b"\x00\x01a" + encode(len(docs)) + docs
        self.assertEqual(list(fts34_history.leaf_tokens(data)), [("a", -2, 0, 0)])

    def test_fts5_round_trips(self):
        for value in (0, 127, 128, 2**32, 2**55):
            data = fts5_history.encode_varint(value)
            self.assertEqual(fts5_history.varint(data, 0), (value, len(data)))

    def test_fts5_truncated_structure(self):
        with self.assertRaises(ValueError):
            fts5_history.parse_segments(b"\x00" * 4 + b"\x01")


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.quiet = redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.temp.cleanup()

    def make_history(self):
        database = make(self.root / "input" / "demo.sqlite")
        report = fts34_history.examine(database, "docs", self.root / "history")
        return database, report, self.root / "history/index-history.json"


class History(Workspace):
    def test_deleted_entry_hidden_from_normal_search(self):
        database, report, _path = self.make_history()
        with sqlite3.connect(database) as connection:
            self.assertEqual(connection.execute("SELECT docid FROM docs WHERE docs MATCH 'lantern'").fetchall(), [])
        old = [r for r in report["documents"] if r["present_in_current_content"] is False]
        self.assertEqual(len(old), 1)
        self.assertEqual(old[0]["doc_id"], 42)
        self.assertEqual(report["errors"], [])
        self.assertTrue(report["source_unchanged"])

    def test_updated_versions_remain_separate(self):
        database = self.root / "versions.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body)")
            connection.execute("INSERT INTO docs(docid,body) VALUES (1,'older lantern')")
            connection.execute("INSERT INTO docs(docid,body) VALUES (100,'retained anchor')")
            connection.commit()
            connection.execute("UPDATE docs SET body='newer notebook' WHERE docid=1")
            connection.commit()
        report = fts34_history.examine(database, "docs", self.root / "history")
        versions = [r for r in report["documents"] if r["doc_id"] == 1]
        self.assertEqual(len(versions), 2)
        self.assertEqual(len({r["segment_id"] for r in versions}), 2)
        self.assertTrue(all(r["present_in_current_content"] for r in versions))

    def test_descending_document_ids(self):
        database = self.root / "descending.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body,order=DESC)")
            connection.executemany("INSERT INTO docs(docid,body) VALUES (?,?)", [(2, "same word"), (8, "same word")])
        report = fts34_history.examine(database, "docs", self.root / "history")
        self.assertEqual({r["doc_id"] for r in report["documents"]}, {2, 8})

    def test_fts3(self):
        database = self.root / "fts3.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts3(body)")
            connection.execute("INSERT INTO docs(docid,body) VALUES (10,'synthetic lantern')")
        report = fts34_history.examine(database, "docs", self.root / "history")
        self.assertEqual(report["documents"][0]["doc_id"], 10)

    def test_contentless_presence_is_unknown(self):
        database = self.root / "contentless.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body,content='')")
            connection.execute("INSERT INTO docs(docid,body) VALUES (12,'synthetic lantern')")
        report = fts34_history.examine(database, "docs", self.root / "history")
        self.assertIsNone(report["documents"][0]["present_in_current_content"])

    def test_large_segment_leaf_pages(self):
        database = self.root / "pages.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body)")
            connection.executemany("INSERT INTO docs(docid,body) VALUES (?,?)", [(i, 'term%06d shared' % i) for i in range(1, 2001)])
        report = fts34_history.examine(database, "docs", self.root / "history")
        self.assertEqual(len(report["documents"]), 2000)
        self.assertFalse(report["errors"])
        self.assertTrue(any(s["first_leaf"] > 0 for s in report["segments"]))

    def test_wal_is_used_without_changing_evidence(self):
        database = self.root / "wal.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body)")
            connection.execute("INSERT INTO docs(docid,body) VALUES (30,'wal lantern')")
            connection.commit()
            before = forensic_io.evidence_files(database)
            report = fts34_history.examine(database, "docs", self.root / "history")
            self.assertEqual(report["documents"][0]["doc_id"], 30)
            self.assertIn("wal.sqlite-wal", report["source_files"])
            self.assertEqual(before, forensic_io.evidence_files(database))
        finally:
            connection.close()

    def test_wrong_table_rejected(self):
        database = self.root / "ordinary.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE docs(body)")
        with self.assertRaises(ValueError):
            fts34_history.examine(database, "docs", self.root / "history")

    def test_existing_destination_is_preserved(self):
        database, _report, _path = self.make_history()
        with self.assertRaises(ValueError):
            fts34_history.examine(database, "docs", self.root / "history")

    def test_fts5_historical_segment(self):
        database = self.root / "fts5.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE VIRTUAL TABLE docs USING fts5(body)")
            connection.execute("INSERT INTO docs(rowid,body) VALUES (42,'old lantern')")
            connection.commit()
            connection.execute("INSERT INTO docs(rowid,body) VALUES (77,'current notebook')")
            connection.commit()
            connection.execute("DELETE FROM docs WHERE rowid=42")
            connection.commit()
        report = fts5_history.examine(database, "docs", self.root / "history")
        self.assertFalse(report["segment_errors"])
        old = [r for r in report["documents"] if r["doc_id"] == 42]
        self.assertTrue(old)
        self.assertTrue(all(r["present_in_current_content_or_docsize"] is False for r in old))
        self.assertTrue(report["source_unchanged"])


class ReindexAndExport(Workspace):
    def test_end_to_end_search(self):
        _database, _report, path = self.make_history()
        target = self.root / "reindexed.sqlite"
        self.assertEqual(reindex.build(path, target, absent_only=True), 1)
        hits = search_index.search(target, ["lantern"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["doc_id"], 42)
        self.assertEqual(hits[0]["retained_terms_unordered"], ["blue", "lantern", "meeting"])
        self.assertFalse(search_index.search(target, ["notebook"]))

    def test_reindex_preserves_two_versions(self):
        _database, report, path = self.make_history()
        first = report["documents"][0]
        report["documents"].append({**first, "segment_id": "synthetic:second"})
        path.write_text(json.dumps(report))
        target = self.root / "reindexed.sqlite"
        self.assertEqual(reindex.build(path, target), 3)
        self.assertEqual(len(search_index.search(target, ["lantern"])), 2)

    def test_reindex_rejects_duplicate_identity(self):
        _database, report, path = self.make_history()
        report["documents"].append(report["documents"][0])
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            reindex.build(path, self.root / "reindexed.sqlite")

    def test_reindex_rejects_errors(self):
        _database, report, path = self.make_history()
        report["errors"] = [{"error": "synthetic failure"}]
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            reindex.build(path, self.root / "reindexed.sqlite")

    def test_reindex_rejects_unverified_source(self):
        _database, report, path = self.make_history()
        report["source_unchanged"] = False
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            reindex.build(path, self.root / "reindexed.sqlite")

    def test_missing_body_column_rejected(self):
        _database, _report, path = self.make_history()
        with self.assertRaises(ValueError):
            reindex.build(path, self.root / "reindexed.sqlite", body_column="missing")

    def test_existing_index_not_overwritten(self):
        _database, _report, path = self.make_history()
        target = self.root / "reindexed.sqlite"
        reindex.build(path, target)
        before = forensic_io.digest(target)
        with self.assertRaises(FileExistsError):
            reindex.build(path, target)
        self.assertEqual(forensic_io.digest(target), before)

    def test_html_escapes_untrusted_terms(self):
        _database, report, path = self.make_history()
        report["documents"][0]["columns"]["0"][0]["terms"] = ["<script>alert(1)</script>"]
        path.write_text(json.dumps(report))
        target = self.root / "terms.html"
        export_terms.render(path, target)
        text = target.read_text()
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("not original sentences", text)

    def test_html_rejects_untrusted_presence_values(self):
        _database, report, path = self.make_history()
        report["documents"][0]["present_in_current_content"] = "<script>alert(1)</script>"
        path.write_text(json.dumps(report))
        target = self.root / "terms.html"
        with self.assertRaises(ValueError):
            export_terms.render(path, target)
        self.assertFalse(target.exists())

    def test_search_treats_boolean_word_literally(self):
        _database, _report, path = self.make_history()
        target = self.root / "reindexed.sqlite"
        reindex.build(path, target)
        self.assertEqual(search_index.search(target, ["OR"]), [])

    def test_search_rejects_empty_query(self):
        with self.assertRaises(ValueError):
            search_index.search(self.root / "does-not-exist", ["???"])


class EvidenceSafety(Workspace):
    def test_path_traversal_rejected(self):
        for value in ("../outside", "/outside", "a/../../outside", "a\\outside", "."):
            with self.assertRaises(ValueError):
                forensic_io.safe_path(self.root, value)

    def test_parent_symlink_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            forensic_io.safe_path(self.root, "linked/payload")

    def test_changed_source_detected(self):
        database = self.root / "evidence.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE data(value)")
        with self.assertRaisesRegex(ValueError, "changed"):
            with forensic_io.snapshot(database):
                with database.open("ab") as stream:
                    stream.write(b"synthetic change")

    def test_sidecar_symlink_rejected(self):
        database = self.root / "evidence.sqlite"
        database.write_bytes(b"synthetic")
        (self.root / "evidence.sqlite-wal").symlink_to(database)
        with self.assertRaises(ValueError):
            with forensic_io.snapshot(database):
                pass

    def test_analyzer_rejects_database_symlink(self):
        database = make(self.root / "input" / "demo.sqlite")
        linked = self.root / "linked.sqlite"
        linked.symlink_to(database)
        with self.assertRaises(ValueError):
            fts34_history.examine(linked, "docs", self.root / "history")

    def test_database_inventory_contains_counts_only(self):
        database = self.root / "ordinary.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE data(body)")
            connection.execute("INSERT INTO data VALUES ('unpublished synthetic content')")
        report = inspect_database.inspect(database, self.root / "inventory")
        self.assertEqual(report["tables"][0]["rows"], 1)
        self.assertNotIn("unpublished synthetic content", json.dumps(report))

    def test_related_selection_excludes_media_and_other_apps(self):
        domain = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared"
        self.assertTrue(related_data_rules.is_related_file(domain, "ChatStorage.sqlite-wal"))
        self.assertTrue(related_data_rules.is_related_file(domain, "ChatSearchV4.sqlite"))
        self.assertFalse(related_data_rules.is_related_file(domain, "Message/Media/synthetic/a.db"))
        self.assertFalse(related_data_rules.is_related_file("AppDomain-com.example.other", "ChatStorage.sqlite"))
        self.assertFalse(related_data_rules.is_related_file(domain, "../ChatStorage.sqlite"))

    def test_inventory_hash_mismatch_rejected(self):
        path = self.root / "inventory.json"
        path.write_text(json.dumps({"files": [{"domain": "AppDomain-net.whatsapp.WhatsApp",
            "relative_path": "ChatStorage.sqlite", "file_id": "0" * 40}]}))
        with self.assertRaises(ValueError):
            related_data_rules.load_related_inventory(path)


class BackupAndCapture(Workspace):
    def make_backup(self):
        backup = self.root / "backup"
        backup.mkdir()
        domain = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared"
        relative = "ChatStorage.sqlite"
        file_id = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        (backup / file_id[:2]).mkdir()
        (backup / file_id[:2] / file_id).write_bytes(b"synthetic raw database payload")
        with sqlite3.connect(backup / "Manifest.db") as connection:
            connection.execute("CREATE TABLE Files(fileID,domain,relativePath,file)")
            connection.execute("INSERT INTO Files VALUES (?,?,?,NULL)", (file_id, domain, relative))
        with (backup / "Manifest.plist").open("wb") as stream:
            plistlib.dump({"IsEncrypted": False}, stream)
        return backup

    def test_unencrypted_backup_copy_is_verified(self):
        backup = self.make_backup()
        target = self.root / "extracted"
        self.assertEqual(inspect_backup.inspect(backup, target), 0)
        report = json.loads((target / "extraction-report.json").read_text())
        entry = report["files"][0]
        self.assertEqual(forensic_io.digest(target / entry["path"]), entry["sha256"])
        self.assertTrue(report["complete"])

    def test_backup_rejects_unsafe_relative_paths(self):
        with self.assertRaises(ValueError):
            inspect_backup.safe_relative("AppDomain-net.whatsapp.WhatsApp", "../ChatStorage.sqlite")

    def test_existing_backup_output_not_overwritten(self):
        backup = self.make_backup()
        target = self.root / "existing"
        target.mkdir()
        with self.assertRaises(FileExistsError):
            inspect_backup.inspect(backup, target)

    def test_capture_plan_has_no_device_side_effects(self):
        with patch("sys.argv", ["capture_whatsapp.py", "--destination", str(self.root / "capture")]), \
             patch("subprocess.Popen") as popen:
            self.assertEqual(capture_whatsapp.main(), 0)
        popen.assert_not_called()
        self.assertFalse((self.root / "capture").exists())

    def test_capture_uses_current_interpreter(self):
        import sys
        command = capture_whatsapp.command_for(self.root / "capture")
        self.assertEqual(command[0], sys.executable)
        self.assertIn("--no-patch-manifest", command)
        self.assertNotIn("restore", command)

    def test_related_capture_requires_exact_inventory(self):
        with self.assertRaises(ValueError):
            capture_whatsapp.command_for(self.root / "capture", include_related=True)

    def test_unencrypted_payload_passthrough(self):
        self.assertEqual(decrypt_whatsapp.decode_payload(b"synthetic", False), b"synthetic")


if __name__ == "__main__":
    unittest.main()
