# Interpretation and limits

An FTS index maps terms to document identifiers and positions. Historical
segments can hold earlier document versions which ordinary queries suppress.
That behavior makes the index useful for investigating retained data, but the
index does not by itself establish who wrote a message or when it was sent.

## Preserve the distinctions

- **Indexed term:** a value extracted from a particular segment, document,
  column, and position. This is what the parser directly observes.
- **Candidate remnant:** a version whose identifier is absent from the current
  content table. It can warrant further investigation; it is not automatically
  a deleted message. Contentless/external-content FTS3/4 tables report presence
  as unknown when no internal content table exists.
- **Attributed record:** a candidate tied to a conversation or sender using
  independently validated schema/identifier evidence. The public scripts do
  not guess that mapping from the original case.
- **Possible reconstruction:** a proposed sentence inferred from terms. This
  release does not generate or publish sentence guesses.

The original investigation's FTS4 store had lost useful original word order and
repetitions before the terms were read. Other indexes may preserve meaningful
positions. The parsers retain observed positions and keep segment versions
separate; the HTML and search outputs deliberately display unordered term sets.

An attachment marker does not mean the attachment was recovered. Document-ID
order and segment-ID order do not establish conversation chronology. The tools
make no promise about exact timestamps, punctuation, capitalization, missing
messages, or reconstructing the original transcript.

## Re-indexing means a new analysis database

`reindex.py` creates a separate database from a history report. It retains
segment/document references, the full column map, and the report's hash. The
report's source hash is carried as a reported value; the re-indexer does not
independently revalidate the original device or database from that hash.

Search indexes sorted term sets. Multiple search words are treated as a
conjunction. Phrase searches would describe that artificial ordering, so the
search command only accepts literal words. Repeated historical versions may
appear as separate hits; that is intentional.

## Scope

The original result concerned retained local application data after a chat was
cleared. It required local device/backup access and the existing backup
password. It did not demonstrate a break of WhatsApp's transport encryption or
recovery from an arbitrary account.

The FTS3/4 parser reads leaves referenced by existing segment-directory records.
It does not carve unallocated disk sectors or recover segments no longer
referenced there. Prefix/language indexes may add further versions and should
be interpreted using the table configuration. Decoding errors are recorded and
cause a nonzero exit.

The FTS5 probe reconstructs one segment at a time in a disposable database.
It is experimental and tied to SQLite's internal representation. It rejects
contentless-delete tables. A successful synthetic regression test is not a
compatibility guarantee for all SQLite builds or application schemas.

## Primary format references

- [SQLite FTS3/4 data structures](https://sqlite.org/fts3.html#_data_structures)
- [SQLite FTS5 data structures](https://sqlite.org/fts5.html#fts5_data_structures)
- [SQLite write-ahead logging](https://sqlite.org/wal.html)
- [pymobiledevice3 source and documentation](https://github.com/doronz88/pymobiledevice3)
- [pyiosbackup source](https://github.com/matan1008/pyiosbackup)
