local container = require "cert.container"
local signature = require "cert.signature"

local function resolvePath(path)
    if path:sub(1, 1) ~= "/" then
        path = fs.combine(shell and shell.dir() or "", path)
    end
    return fs.combine(path)
end

if not fs.exists("/disk/ca.pem") or not fs.exists("/disk/ca.key") then
    printError("No CA files found on disk.")
    print("Insert the disk containing your CA key and certificate.")
    print("Expected files: /disk/ca.pem and /disk/ca.key")
    return
end

local target = ...
if not target then
    print("Usage: pki-sign <file>")
    print()
    print("Signs a file with the CA key from disk.")
    print("The signature is saved as <file>.pk7")
    return
end

local path = resolvePath(target)
if not fs.exists(path) then
    printError("File not found: " .. path)
    return
end

local file = fs.open("/disk/ca.pem", "rb")
local certPem = file.readAll()
file.close()

file = fs.open("/disk/ca.key", "rb")
local keyPem = file.readAll()
file.close()

file = fs.open(path, "rb")
local data = file.readAll()
file.close()

print("Signing " .. path .. " with CA key...")

require "ccryptolib.random".initWithTiming()

local cert = container.loadX509(container.decodePEM(certPem))
local key = container.loadPKCS8(container.decodePEM(keyPem))
local pk7 = signature.sign(cert, key, data)
local sigDer = container.savePKCS7(pk7)

local sigPath = path .. ".pk7"
file = fs.open(sigPath, "wb")
if not file then
    printError("Could not write signature to " .. sigPath)
    return
end
file.write(sigDer)
file.close()

term.setTextColor(colors.lime)
print("Signed! Signature saved to " .. sigPath)
term.setTextColor(colors.white)
