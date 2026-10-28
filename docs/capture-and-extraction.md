# Capture and extraction

The analysis commands work offline on existing files. These optional commands
use the original investigation's local iPhone backup approach. They are intended
for a device and backup you own or have explicit permission to inspect.

## Capture the main database

Use the Python 3.12 virtual environment from the README. Connect the iPhone by
USB and complete its ordinary trust and backup approvals on the phone.

```sh
.venv/bin/python capture_whatsapp.py --destination local/captures/first
.venv/bin/python capture_whatsapp.py --destination local/captures/first --run
```

The first command only prints a plan. The second starts a new capture. It keeps
WhatsApp's main chat database/log payloads and backup metadata; the phone still
sends the full stream. Other app payloads are discarded by the filtered
receiver, reducing disk use rather than USB transfer volume.

The wrapper checks physical space and stops before consuming its 1.5 GiB
reserve. It preserves existing backup encryption and refuses the standard
Apple backup directory. Do not run a device restore from this partial capture.

## Unlock and inventory

Find the device subdirectory containing `Manifest.plist` and `Manifest.db` in
the completed capture. Pass its explicit path as `BACKUP_DIRECTORY` below.

```sh
.venv/bin/python decrypt_whatsapp.py BACKUP_DIRECTORY --destination local/extracted-main
.venv/bin/python decrypt_whatsapp.py BACKUP_DIRECTORY --inventory-only --destination local/inventory
```

For encrypted captures, enter the **local Finder/iPhone backup password** at the
hidden Terminal prompt. The tools do not accept it on the command line, save
it, or query Keychain. A partial capture's manifest can list files whose bytes
were discarded; an inventory entry is not proof that a payload was captured.

## Include search indexes and related databases

The original investigation needed an additional pass to retain the separate
search store. A filename-only filter did not select every hashed payload. The
broader path matches payload identifiers against an explicit manifest inventory.

```sh
.venv/bin/python capture_whatsapp.py --destination local/captures/related --include-related --related-inventory local/inventory/whatsapp-file-inventory.json --filtered-capacity 40
.venv/bin/python capture_whatsapp.py --destination local/captures/related --include-related --related-inventory local/inventory/whatsapp-file-inventory.json --filtered-capacity 40 --run
.venv/bin/python decrypt_whatsapp.py RELATED_BACKUP_DIRECTORY --include-related --destination local/extracted-related
```

`--filtered-capacity 40` is an advanced compatibility option recovered from the
low-storage case. It reports **logical** capacity for the outgoing full stream
while discarded files consume no retained storage. Real physical space remains
guarded in the receiver and parent process. This is not extra disk space, and
the backend is restricted to `pymobiledevice3==11.34.1`. The release has not
retested that backend against a connected device.

Selection excludes media by default. Optional media selection accepts only a
small explicit list checked against the same manifest. The public repository
does not contain such a list.

## Inspect the extracted files

Use `inspect_database.py` on individual databases to establish their schema and
FTS version, then follow the analysis commands in the README. Keep all captured
sidecars next to their database. Never run SQLite `rebuild`, `optimize`, or a
restore against preserved evidence; the provided re-indexer writes a different
analysis database.

Exit codes: `0` means the operation completed; `2` indicates an input or runtime
failure; `3` is used by capture for the low-space stop and by raw inspection for
encrypted backups; `4` indicates missing selected files or segment decode
errors, depending on the command; `130` indicates interrupted capture.
