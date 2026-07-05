# CCSecureBoot PKI

A [NeoForge](https://neoforged.net/) mod for Minecraft 1.21.1 that adds Public Key Infrastructure (PKI) management to [CC: Tweaked](https://tweaked.cc/) and [CCSecureBoot](https://github.com/SquidDev-CC/CCSecureBoot).

Generate your own Certificate Authority on a floppy disk, install it as the root of trust, and sign boot files for verified PXBoot.

## Requirements

| Dependency | Version |
|---|---|
| Minecraft | 1.21.1 |
| NeoForge | 21.1.x |
| CC: Tweaked | 1.119.0+ |
| CCSecureBoot | 1.0.2+ |

## Installation

1. Download the latest release JAR from [Releases](https://github.com/p4ncak3s-R0ck/CC-Secure-Boot-PKI/releases).
2. Place the JAR in your server's `mods/` folder.
3. Start the server. The mod will initialize and register the `pki` API with ComputerCraft.

## Building from Source

```bash
git clone https://github.com/p4ncak3s-R0ck/CC-Secure-Boot-PKI.git
cd CC-Secure-Boot-PKI
./gradlew build
```

The output JAR will be in `build/libs/`.

## Usage

Once installed, each ComputerCraft computer gains access to the `pki` API. See the following docs:

- [Lua API Reference](API.md) — Full API documentation for the `pki` module.
- [CLI Programs](PROGRAMS.md) — Built-in ROM programs for managing certificates.

### Quick Start

1. Insert a floppy disk into a computer.
2. Run `gen-ca` to generate a Certificate Authority and save it to the disk.
3. Run `install-ca` to install the CA as the server's root of trust.
4. Use `pki-sign <file>` to sign boot files with your CA key.
5. Enroll computers with CCSecureBoot's `enroll-secure-boot` program.

## How It Works

CCSecureBoot PKI provides a server-side PKI layer for CC: Tweaked:

- **Certificate Authority**: Ed25519 key pairs with 30-year self-signed X.509 certificates, generated via BouncyCastle.
- **Trust Store**: CA certificates are stored per-world in `certs/` and per-computer in `certs/computer-<id>/`.
- **CMS Signatures**: Files are signed using PKCS#7/CMS `SignedData` with Ed25519, verifiable by CCSecureBoot.
- **Floppy-based Key Storage**: CA private keys live on floppy disks, never on the server filesystem.

## License

This project is licensed under the [GNU General Public License v3.0](../LICENSE).
