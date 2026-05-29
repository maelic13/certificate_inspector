# Changelog

All notable changes to this project are documented here.

## 1.0.0 - 2026-05-29

- Initial release of Certificate Inspector.
- Added Firefox certificate-chain inspection using `webRequest.getSecurityInfo()`.
- Added local/system/imported root detection using Firefox certificate root metadata.
- Added toolbar status icons for Firefox built-in trust, local/system trust, certificate problem, and unknown states.
- Added a readable popup summary with expandable certificate details.
- Added a calmer toolbar update flow to avoid icon flicker during page loads.
- Added light/dark friendly styling and release build scripts.
- Released under GPL-3.0-or-later.
