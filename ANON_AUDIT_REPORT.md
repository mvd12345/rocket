# Anonymization Audit Report

## Scope
This report documents the sanitization steps applied to the artifact repository for double-blind review.

## Removed / Pruned
- Removed VCS metadata and history (fresh `.git` with a single anonymized commit).
- Removed build outputs and generated artifacts: `target/`, `out/`, `jar_file/`, `demo/output/`.
- Removed generated reports and stray artifacts (e.g., `Report/`, `*.bak`, `*.temp`, `*.txt`).
- Removed local IDE and cache directories.

## Scrubbed / Rewritten
- Rewrote `README.md`, added `REPRODUCE.md`, `QUICKSTART.md`, and `OPEN_SCIENCE_APPENDIX.md` with neutral language.
- Removed absolute path examples and author-specific strings from source comments.
- Adjusted `pom.xml` header to avoid embedded URLs.
- Added `scripts/self_check.sh` with path redaction in output.
- Restored `src/main/resources/config/_files.txt` required for startup validation.

## Automated Scan
Command:
```bash
SOURCE_REPO=/path/to/source ./tools/anon_scan.sh
```
Result: `anon_scan: no findings`

## Git State (Proof)
```
commit <redacted>
Author:     <redacted>
AuthorDate: Thu Jan 1 00:00:00 2026 +0000
Commit:     <redacted>
CommitDate: Thu Jan 1 00:00:00 2026 +0000

    Artifact for double-blind review
```

## Reviewer Verification Commands
```bash
./tools/anon_scan.sh
./scripts/self_check.sh
git log -1 --format=fuller
git remote -v
git submodule status
```
