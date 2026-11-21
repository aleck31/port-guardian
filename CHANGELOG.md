# Changelog

## Unreleased

## v0.5.0 — 2026-11-21

### Added

- Install Port Guardian as a PWA on desktop and on a phone's home screen.
- Sign in with TOTP MFA: users who have an authenticator app enabled are asked for a code after their password.
- See how many addresses a CIDR grants, on the IP card before adding and on each whitelist entry; blocks of a /16 or wider are highlighted.
- `max_prefix_len` in `config.yaml` sets the widest block a single IP may whitelist (default /16).
- `lambda.log_retention_days` in `config.yaml` sets CloudWatch log retention on deploy.

### Changed

- Clients inside AWS's published IP ranges are whitelisted as a single address (/32) instead of a block of provider space.
- Account IDs and Cognito settings are read only from `config.yaml`; a missing value now fails the deploy instead of falling back to a built-in default.

### Fixed

- The whitelist entries table no longer makes the page scroll sideways on phone widths.
- `setup.py` passes the configured deploy region and `--profile` through to `chalice deploy`, so deploys no longer depend on the shell's AWS environment.
