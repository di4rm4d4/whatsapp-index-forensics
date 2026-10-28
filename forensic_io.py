# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Copy and verify SQLite evidence before handing it to SQLite."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def safe_path(root, relative):
    """Reject traversal and symbolic links, including intermediate directories."""
    relative = str(relative)
    parts = PurePosixPath(relative)
    if not relative or parts.is_absolute() or ".." in parts.parts or "\\" in relative:
        raise ValueError("Unsafe relative evidence path.")
    root = Path(root).resolve(strict=True)
    candidate = root
    for part in parts.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("Symbolic links are not accepted as evidence paths.")
    if candidate == root or root not in candidate.resolve().parents:
        raise ValueError("Evidence path is outside its source directory.")
    return candidate


def separate_output(source, destination):
    source = Path(source).expanduser().resolve(strict=True)
    destination = Path(destination).expanduser().resolve()
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("Output must not overlap the preserved source.")
    return destination


def write_json(path, value):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def evidence_files(database):
    found = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = database.with_name(database.name + suffix)
        if path.is_symlink():
            raise ValueError("Symbolic-link databases and sidecars are not accepted.")
        if path.is_file():
            found[path.name] = {"sha256": digest(path), "bytes": path.stat().st_size}
    if database.name not in found:
        raise ValueError("Input is not a database file.")
    return found


@contextmanager
def snapshot(database):
    """Yield a temporary connection and hashes; check originals again on exit.

    WAL and rollback journals travel with the copy. SQLite may create or change
    sidecars in the disposable directory; it never opens the source itself.
    Use a completed, stable capture, rather than a live application database.
    """
    database = Path(database).expanduser()
    if database.is_symlink():
        raise ValueError("Symbolic-link inputs are not accepted.")
    database = database.resolve(strict=True)
    before = evidence_files(database)
    with tempfile.TemporaryDirectory(prefix="wa-evidence-") as temp:
        copied = Path(temp) / database.name
        for name, expected in before.items():
            target = Path(temp) / name
            shutil.copyfile(database.parent / name, target)
            target.chmod(0o600)
            if digest(target) != expected["sha256"]:
                raise ValueError("Evidence copy failed hash verification.")
        connection = None
        try:
            connection = sqlite3.connect(copied)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            yield connection, before
        finally:
            if connection is not None:
                connection.close()
            if evidence_files(database) != before:
                raise ValueError("Source files changed during analysis; use a stable capture.")
