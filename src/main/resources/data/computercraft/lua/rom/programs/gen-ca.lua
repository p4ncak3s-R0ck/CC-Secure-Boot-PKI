local pki = require "pki"

if not fs.isDir("/disk") then
    print("Please insert a floppy disk to save the Certificate Authority key.")
    while not fs.isDir("/disk") do os.pullEvent("disk") end
end

print("=== Generate Certificate Authority ===")
print("This will create a new Ed25519 CA key pair and self-signed certificate.")
write("Enter a COMMON NAME for your Certificate Authority: ")
local commonName = read()
while commonName == "" do
    write("Name must not be empty.\nEnter a name: ")
    commonName = read()
end

print()
write("Enter a ORGANIZATION NAME for your Certificate Authority: ")
local organizationName = read()
while organizationName == "" do
    write("Name must not be empty.\nEnter a name: ")
    organizationName = read()
end

print()
write("Enter a ORGANIZATIONAL UNIT for your Certificate Authority: (Optional)")
local organizationUnit = read()

print()
write("Enter a STATE for your Certificate Authority: (Optional)")
local state = read()

print()
write("Enter a COUNTRY for your Certificate Authority: (Optional)")
local country = read()

print()
print("Generating CA key pair and certificate...")
local ok, result = pcall({
    CN=commonName,
    O=organizationName,
    OU=organizationUnit,
    S=
    })
if not ok then
    printError("Failed to generate CA: " .. result)
    return
end

local caKey = result.key
local caCert = result.cert

local keyPath = "/disk/ca.key"
local certPath = "/disk/ca.pem"

local file = fs.open(keyPath, "wb")
if not file then
    printError("Could not write CA key to disk. Is it writable?")
    return
end
file.write(caKey)
file.close()

file = fs.open(certPath, "wb")
if not file then
    printError("Could not write CA certificate to disk.")
    fs.delete(keyPath)
    return
end
file.write(caCert)
file.close()

term.setTextColor(colors.lime)
print("Certificate Authority generated successfully!")
term.setTextColor(colors.white)
print()
print("Key saved to: " .. keyPath)
print("Certificate saved to: " .. certPath)
print()
term.setTextColor(colors.yellow)
print("KEEP THIS DISK SAFE. Anyone with the CA key can sign")
print("boot files for any computer enrolled with this CA.")
print()
term.setTextColor(colors.lightBlue)
print("Next steps:")
print("1. Run 'install-ca' to install this CA as the root of trust")
print("2. Use 'pki-sign <file>' to sign boot files")
print("3. Enroll computers with 'enroll-secure-boot' (from CCSecureBoot)")
term.setTextColor(colors.white)
