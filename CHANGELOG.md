# Changelog

All notable changes to this audit and its deliverables.

## [v4.0] — 2026-03
### Added
- PoC consistency check: every script cross-referenced against confirmed findings.
- Usage guide for the full PoC suite inside the report.
- Author credit (`deepquest`, blog URL) and version headers across all scripts.
### Changed
- `poc_01_hardcoded_secrets.py` → v1.1: corrected target library names (no `libline.so`
  in 26.1.1), added 8 LINE-specific patterns (Sentry DSN, legy endpoints, DLK tokens,
  prefixed-JWT, GCP project IDs), replaced demo data with real F-04/F-05 findings.
- `poc_03_cert_pinning.py` → v1.2: domain list expanded from 8 generic to 16 confirmed
  real domains; F-01 reclassified HIGH → CRITICAL (cleartext auth); added `MUST_BE_HTTPS`
  list and staging-domain detection.
- `run_all_pocs.py` → v1.1, `analyze_line_natives.py` → v1.1: paths updated for the
  real 26.1.1 bundle layout.

## [v3.0] — 2026-03
### Added
- "About LINE" overview: company, user base (~194M MAU), and financial context.
- Target high-value-asset rationale tied to the 2024 breach history.

## [v2.0] — 2026-03
### Added
- Eight confirmed findings (F-01…F-08) with evidence, impact, and remediation.
- Six documented false positives from the P0 native scan with entropy reasoning.

## [v1.0] — 2026-02
### Added
- Initial PoC suite (5 scripts + master runner) and baseline audit report.
- Reproduction and environment guides (Kali + macOS/Ghidra).
