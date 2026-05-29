# Certificate Inspector

Firefox extension for spotting local or enterprise TLS trust at a glance. Useful for spotting proxy.

It shows whether the active HTTPS site uses a certificate chain rooted in Firefox's built-in trust store or a root certificate imported from the operating system, enterprise policy, or local user configuration.

## Status Colors

- Green/teal: trusted by a Firefox built-in root certificate
- Amber/yellow: trusted by a local, system, enterprise, or imported root certificate
- Red: certificate or TLS problem
- Gray: unknown, internal page, or no captured certificate yet

## What It Detects

The extension asks Firefox for TLS details with `webRequest.getSecurityInfo()` and checks the root certificate in the chain.

The amber/yellow state means Firefox trusts the connection, but the root certificate is not one of Firefox's built-in roots. This commonly happens with corporate TLS inspection, security products, local development CAs, or manually imported certificate authorities.

The popup focuses on the readable certificate summary: verified by, root certificate, trust source, valid host, and expiration date. More TLS details are available behind an expandable section.

## Install

Certificate Inspector is **not published on addons.mozilla.org**. Install it from the signed `.xpi` attached to this repository's GitHub releases:

- [Latest release](https://github.com/maelic13/ff_certificate_ext/releases/latest)
- [All releases](https://github.com/maelic13/ff_certificate_ext/releases)

Download `certificate-inspector-<version>.xpi` from the latest release and open it with Firefox.

Minimum supported version is Firefox 142 on desktop. Firefox for Android is not supported.

## Development

```powershell
npm install
npm run lint
npm run
```

You can also load it manually:

1. Open Firefox `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on**.
3. Select `manifest.json` from this folder.
4. Reload the site you want to inspect.

Temporary add-ons are removed when Firefox restarts.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
