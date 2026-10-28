# Release scope

This is a reusable release derived from an October 2026 recovery investigation.
It is not an upload of the private case directory.

## Adapted from the investigation

- Main-database and manifest-inventory capture wrappers.
- The pinned filtered receiver and small-support-file selection rules.
- Local password-based extraction and unencrypted-backup inspection.
- FTS3/4 leaf parsing and experimental FTS5 segment reconstruction.

## Added for the public release

- A common verified-copy layer that includes SQLite sidecars.
- Generic database inventory, with schemas and counts rather than row content.
- A separate searchable analysis index and literal-word search command.
- An escaped offline term report, replacing a case-specific report generator.
- Generated demonstrations and regression tests.
- Explicit limits, a licence, dependency notices, and a CI workflow.

## Excluded

Private captures, manifests, device/account identifiers, phone numbers, media,
message text, private exports, hardcoded sentence guesses, and the original
case's contact-attribution mappings. The old Mac/iCloud-cache exploration is
also excluded because it was a case-specific diagnostic path.

## What was tested for this release

Core tests operate on generated FTS3/4 and FTS5 databases, synthetic backup
manifests, and temporary files. They verify the discovery/re-index/search
pipeline, version separation, WAL preservation, malformed data handling, output
escaping, source hashes, path handling, and capture planning. The CI workflow
runs those checks on multiple Python versions and smoke-checks the pinned
receiver imports separately.

No connected phone or real encrypted backup is accessed by the test suite.
Live capture, trust prompts, Keybag password acceptance, and current iOS or
WhatsApp compatibility remain separate from the synthetic validation.
