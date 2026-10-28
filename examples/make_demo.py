#!/usr/bin/env python3
# Copyright (C) 2026 Diana McDermott
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create a synthetic FTS4 database with a deleted, historical index entry."""

import argparse
import os
from pathlib import Path
import sqlite3


def make(database):
    database = Path(database)
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.close(os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE VIRTUAL TABLE docs USING fts4(body,sender,chat,kind)")
        connection.execute("INSERT INTO docs(docid,body,sender,chat,kind) VALUES (42,?,?,?,?)",
                           ("blue lantern meeting", "synthetic_sender", "synthetic_chat", "text"))
        connection.commit()
        connection.execute("INSERT INTO docs(docid,body,sender,chat,kind) VALUES (77,?,?,?,?)",
                           ("current notebook", "synthetic_sender", "synthetic_chat", "text"))
        connection.commit()
        connection.execute("DELETE FROM docs WHERE docid=42")
        connection.commit()
    finally:
        connection.close()
    print("Synthetic FTS4 database:", database)
    return database


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    make(parser.parse_args().database)
