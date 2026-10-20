# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-20

### Added
- Token discovery by SHA-256 fingerprint across config files, environment and running processes
- Atomic multi-file token replacement with automatic rollback
- Four-step fail-closed verification: new token live, old token revoked, zero runtime holders, zero config copies
- Drift watch mode that alerts when an old token reappears
