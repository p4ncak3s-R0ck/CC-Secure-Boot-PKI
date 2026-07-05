# Lua API Reference

The `pki` API is available on all ComputerCraft computers when CCSecureBoot PKI is installed. Access it via:

```lua
local pki = require "pki"
```

All functions operate on PEM-encoded data passed as Lua strings (or binary strings from `fs.read`/`string.byte`).

---

## `pki.generateCA(name)`

Generates a new Ed25519 Certificate Authority key pair and self-signed X.509 certificate.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `name` | `string` | Common Name (CN) for the CA subject. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `key` | `string` | PEM-encoded PKCS#8 Ed25519 private key. |
| `cert` | `string` | PEM-encoded X.509 v3 certificate. |

**Certificate Properties:**

- Algorithm: Ed25519
- Serial: 32 random bytes
- Validity: 30 years from generation
- Subject: `CN=<name>`

**Example:**

```lua
local pki = require "pki"
local result = pki.generateCA("MyCA")
fs.open("/disk/ca.key", "wb").write(result.key)
fs.open("/disk/ca.pem", "wb").write(result.cert)
```

---

## `pki.sign(keyPem, certPem, data)`

Signs arbitrary data using a PKCS#7/CMS `SignedData` structure with Ed25519.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `keyPem` | `string` | PEM-encoded PKCS#8 Ed25519 private key. |
| `certPem` | `string` | PEM-encoded X.509 certificate matching the key. |
| `data` | `string` | The data to sign. |

**Returns:**

| Type | Description |
|---|---|
| `string` | DER-encoded PKCS#7 `SignedData` CMS envelope. |

**Example:**

```lua
local key = fs.open("/disk/ca.key", "rb").readAll()
local cert = fs.open("/disk/ca.pem", "rb").readAll()
local boot = fs.open("/startup", "rb").readAll()
local sig = pki.sign(key, cert, boot)
fs.open("/startup.pk7", "wb").write(sig)
```

---

## `pki.installCA(certPem)`

Installs a CA certificate as the server's root of trust. This writes the certificate to the world's `certs/root.pem` and registers it for the calling computer.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `certPem` | `string` | PEM-encoded X.509 CA certificate. |

**Returns:**

| Type | Description |
|---|---|
| `boolean` | `true` on success, `false` on failure. |
| `string` | (on failure) Error message. |

**Side Effects:**

- Creates `certs/root.pem` in the world folder (replaces existing root).
- Creates `certs/computer-<id>/<safeName>.pem` for the calling computer.

**Example:**

```lua
local cert = fs.open("/disk/ca.pem", "rb").readAll()
local ok, err = pki.installCA(cert)
if ok then
    print("CA installed as root of trust")
else
    printError("Failed: " .. tostring(err))
end
```

---

## `pki.uninstallCA(certPem)`

Removes a CA certificate from the trust store.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `certPem` | `string` | PEM-encoded X.509 certificate to remove. |

**Returns:**

| Type | Description |
|---|---|
| `boolean` | `true` on success, `false` on failure. |
| `string` | (on failure) Error message. |

**Side Effects:**

- Removes `certs/computer-<id>/<safeName>.pem` for the calling computer.
- If the removed certificate matches `certs/root.pem`, deletes the root and any `root.key`.

---

## `pki.getComputerRoots()`

Returns the list of CA certificates installed for the calling computer.

**Returns:**

| Type | Description |
|---|---|
| `string[]` or `nil` | Array of PEM-encoded certificate strings, or `nil` if none exist. |

---

## `pki.getInstalledCAs()`

Returns detailed information about all CA certificates installed for the calling computer.

**Returns:**

| Type | Description |
|---|---|
| `table[]` or `nil` | Array of tables, or `nil` if none exist. |

**Table Fields:**

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Common Name (CN) extracted from the subject. |
| `subject` | `string` | Full X.500 subject DN. |
| `pem` | `string` | PEM-encoded certificate. |

---

## `pki.exportRoot()`

Exports the server's current root CA key and certificate.

**Returns:**

| Type | Description |
|---|---|
| `table` or `nil` | Table with `key` and `cert` fields (PEM strings), or `nil` if no root exists. |

**Table Fields:**

| Field | Type | Description |
|---|---|---|
| `key` | `string` | PEM-encoded private key (`root.key`). |
| `cert` | `string` | PEM-encoded certificate (`certs/root.pem`). |

---

## `pki.getStatus()`

Returns the current PKI status for the server and calling computer.

**Returns:**

| Field | Type | Description |
|---|---|---|
| `rootInstalled` | `boolean` | Whether a root CA certificate exists. |
| `enrolledComputers` | `number` | Number of computers with installed CAs. |
| `thisComputerEnrolled` | `boolean` | Whether the calling computer has a CA installed. |
| `worldPath` | `string` | Path to the world folder. |
