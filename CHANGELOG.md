# Changelog

## Unreleased

### Added

- Prefix lists that differ from the primary list are flagged in the UI, along with entries missing from some lists; **Review sync** previews the changes per list, with each entry's description, and warns if one would remove your current IP's access.
- Choose how long an entry lasts when adding it — never, or 1, 7, 30, 90 or 180 days — and set an exact expiry date when editing it. Expired entries are removed from every list each day at 00:05 (UTC+8). Entries that never expire are still retired by FIFO, or kept with a pin.
- **+ Add entry** adds any public IPv4 CIDR (up to a /16) with a description, and each entry can be edited to change its description or expiry.
- Entries added outside Port Guardian, such as through the AWS console, are tagged `external`; editing one in Port Guardian clears the tag.

### Changed

- Whitelist writes land on one primary list (primary account, Lambda's region) and every other list is then made identical to it. A failed write can no longer leave the lists diverged, and each write repairs drift left by earlier ones. Entries added by hand to a non-primary list are removed on the next write.
- Only members of the `cognito.admin_group` group (new, required in `config.yaml`) can change the whitelist or SG rules; other signed-in users get a read-only view.
- Descriptions are shown without their internal markers: expiry and creation time have their own columns, and a pin shows as an icon.
- Pinning an entry also clears its expiry.

### Fixed

- Add, delete and pin show a result for every account and region, including which ones failed. The add result box had been hidden by a styling bug, and delete and pin showed nothing.

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
