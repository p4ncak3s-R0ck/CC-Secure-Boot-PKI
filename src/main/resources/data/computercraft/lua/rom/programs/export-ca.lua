local pki = require "pki"

print("=== Export Current Root CA ===")
print("This will export the current root certificate and key from the server.")
print()

if not fs.isDir("/disk") then
    print("Please insert a floppy disk to save the exported CA.")
    while not fs.isDir("/disk") do os.pullEvent("disk") end
end

local ok, root = pcall(pki.exportRoot)
if not ok then
    printError("Failed to export root CA: " .. tostring(root))
    return
end

if not root then
    printError("No root CA is currently installed on this server.")
    print("Run 'gen-ca' first, then 'install-ca' to create and install a CA.")
    return
end

local keyPath = "/disk/exported-ca.key"
local certPath = "/disk/exported-ca.pem"

local file = fs.open(keyPath, "wb")
if not file then
    printError("Could not write key to disk.")
    return
end
file.write(root.key)
file.close()

file = fs.open(certPath, "wb")
if not file then
    printError("Could not write certificate to disk.")
    fs.delete(keyPath)
    return
end
file.write(root.cert)
file.close()

term.setTextColor(colors.lime)
print("Root CA exported successfully!")
term.setTextColor(colors.white)
print("Certificate: " .. certPath)
print("Key: " .. keyPath)
term.setTextColor(colors.yellow)
print("Handle this disk with care!")
