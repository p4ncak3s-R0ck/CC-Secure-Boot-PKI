# CLI Programs

CCSecureBoot PKI ships with several ROM programs for managing certificates from the ComputerCraft shell. These programs are automatically installed into the ROM when the mod is loaded.

---

## `gen-ca`

Generates a new Certificate Authority key pair and saves it to a floppy disk.

```
gen-ca
```

**Workflow:**

1. Prompts for a floppy disk (waits for one to be inserted).
2. Asks for a CA name (Common Name).
3. Generates an Ed25519 key pair and self-signed X.509 certificate.
4. Saves `ca.key` and `ca.pem` to the floppy disk.

**Output Files:**

| File | Description |
|---|---|
| `/disk/ca.key` | PEM-encoded Ed25519 private key (PKCS#8). |
| `/disk/ca.pem` | PEM-encoded X.509 v3 certificate. |

**Security Note:** The CA private key never leaves the floppy disk. Keep this disk safe — anyone with it can sign boot files for enrolled computers.

---

## `install-ca`

Installs a CA certificate from a floppy disk as the server's root of trust.

```
install-ca
```

**Workflow:**

1. Shows any currently installed CAs.
2. Reads `/disk/ca.pem` from the floppy disk.
3. Prompts for confirmation.
4. Installs the certificate as the world root and registers it for this computer.

**Prerequisites:**

- A floppy disk with `ca.pem` (created by `gen-ca`).

---

## `uninstall-ca`

Removes a CA certificate from the trust store.

```
uninstall-ca
```

**Workflow:**

1. Lists all installed CAs with indices.
2. Prompts for which CA to remove.
3. Prompts for confirmation.
4. Removes the certificate from this computer's trust store.

**Warning:** If this was the only CA, computers enrolled with it will no longer boot until a new CA is installed.

---

## `export-ca`

Exports the server's current root CA key and certificate to a floppy disk.

```
export-ca
```

**Workflow:**

1. Prompts for a floppy disk.
2. Exports the root CA key and certificate.
3. Saves `exported-ca.key` and `exported-ca.pem` to the disk.

**Use Case:** Backing up the root CA or migrating it to another server.

**Output Files:**

| File | Description |
|---|---|
| `/disk/exported-ca.key` | PEM-encoded private key. |
| `/disk/exported-ca.pem` | PEM-encoded certificate. |

---

## `pki-sign`

Signs a file using the CA key from a floppy disk.

```
pki-sign <file>
```

**Parameters:**

| Argument | Description |
|---|---|
| `<file>` | Path to the file to sign (relative or absolute). |

**Workflow:**

1. Reads CA key and certificate from `/disk/ca.key` and `/disk/ca.pem`.
2. Reads the target file.
3. Creates a PKCS#7 CMS `SignedData` signature using Ed25519.
4. Saves the signature as `<file>.pk7`.

**Example:**

```
pki-sign /disk/startup
```

This creates `/disk/startup.pk7` containing the DER-encoded CMS signature.

---

## `autorun/pki` (autorun script)

Automatically runs at computer boot. Loads installed CA certificates and injects them into CCSecureBoot's certificate chain validation.

**Behavior:**

1. Fetches the computer's installed root certificates via `pki.getComputerRoots()`.
2. Decodes and parses each PEM certificate.
3. Monkey-patches `cert.chain.validate` to include the PKI roots as additional trust anchors.
4. Filters out self-signed certificates from the chain to prevent duplicate trust.

This script requires no user interaction — it runs silently in the background on every boot.
