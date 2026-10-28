# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared selection rule for WhatsApp databases, indexes and small support files.

Media, profile pictures and sticker payloads are excluded. This rule is used
both for retaining the backup stream and for the later local decryption.
"""

import hashlib
import json
import re
from pathlib import PurePosixPath


RELATED_PATTERN = (
    r"(?i)(?:^|/)(?:AppDomain(?:Group|Plugin)?)-"
    r"[A-Za-z0-9_.]*whatsapp[A-Za-z0-9_.]*(?:/|-)"
    r"(?!Message/Media(?:/|$)|Media(?:/|$)|stickers(?:/|$))"
    r".*(?:\.(?:sqlite3?|sqlitedb|db|sql|plist|json|log|bak|backup|zip|crypt\d*)"
    r"(?:[-.][^/]*)?|backup-buffer|backup_control_file)$"
)
_RELATED = re.compile(RELATED_PATTERN)


def is_related_file(domain, relative_path):
    if not isinstance(domain, str) or not isinstance(relative_path, str):
        return False
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or "\\" in relative_path:
        return False
    return bool(_RELATED.search(domain + "/" + relative_path))


def load_media_inventory(path):
    """Read a small, explicit list of already verified chat media paths."""
    rows = json.loads(path.read_text())
    if not isinstance(rows, list):
        raise ValueError("Expected a media path list.")
    selected = {}
    for row in rows:
        if not row.get("declared_bytes"):
            continue  # Directory entries are not backup payloads.
        if row["domain"] != "AppDomainGroup-group.net.whatsapp.WhatsApp.shared":
            raise ValueError("Media selection must belong to the WhatsApp shared group.")
        if not re.fullmatch(r"Message/Media/[0-9]+@(?:lid|s\.whatsapp\.net)/[A-Za-z0-9/_.-]+", row["relative_path"]):
            raise ValueError("Unexpected media path.")
        if ".." in row["relative_path"].split("/"):
            raise ValueError("Unsafe media path.")
        expected = hashlib.sha1((row["domain"] + "-" + row["relative_path"]).encode()).hexdigest()
        if row["file_id"] != expected:
            raise ValueError("Media identifier does not match its WhatsApp path.")
        selected[expected] = row
    if not selected or len(selected) > 20 or sum(r["declared_bytes"] for r in selected.values()) > 20 * 1024 * 1024:
        raise ValueError("Explicit media selection is empty or exceeds the small-file limit.")
    return selected


def load_related_inventory(path, media_inventory=None):
    report = json.loads(path.read_text())
    selected = {}
    for row in report["files"]:
        if not is_related_file(row["domain"], row["relative_path"]):
            continue
        expected = hashlib.sha1((row["domain"] + "-" + row["relative_path"]).encode()).hexdigest()
        if row["file_id"] != expected:
            raise ValueError("Inventory identifier does not match its WhatsApp path.")
        selected[expected] = row
    if not selected:
        raise ValueError("No WhatsApp data files were selected from this inventory.")
    if media_inventory is not None:
        indexed = {r["file_id"]: r for r in report["files"]}
        for file_id, entry in load_media_inventory(media_inventory).items():
            original = indexed.get(file_id)
            if original is None or any(original.get(k) != entry.get(k) for k in
                                       ("domain", "relative_path", "declared_bytes")):
                raise ValueError("Media selection does not match the verified phone inventory.")
            selected[file_id] = entry
    return report, selected
