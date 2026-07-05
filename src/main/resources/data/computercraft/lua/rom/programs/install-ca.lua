local pki = require "pki"

print("=== Install Certificate Authority ===")

local ok, existing = pcall(pki.getInstalledCAs)
if ok and existing and #existing > 0 then
    print("Currently installed CA(s):")
    for _, ca in ipairs(existing) do
        print("  " .. ca.name .. " (" .. ca.subject .. ")")
    end
    print()
end

if not fs.exists("/disk/ca.pem") then
    printError("No CA certificate found on disk.")
    print("Run 'gen-ca' to create a Certificate Authority, then insert the disk.")
    print()
    print("Expected file: /disk/ca.pem")
    return
end

local file = fs.open("/disk/ca.pem", "rb")
local certPem = file.readAll()
file.close()

term.setTextColor(colors.yellow)
print("WARNING: This will install the CA certificate as the server's root of trust.")
print("It replaces any existing world root and is trusted by this computer.")
print("The CA key stays on the floppy disk - keep it safe!")
term.setTextColor(colors.white)
write("Do you want to install this CA certificate? [y/N] ")
local answer = read()
if answer:lower() ~= "y" and answer:lower() ~= "yes" then
    print("Installation cancelled.")
    return
end

print("Installing CA as root of trust...")
local ok, result = pcall(pki.installCA, certPem)
if not ok then
    printError("Failed to install CA: " .. tostring(result))
    return
end

if result then
    term.setTextColor(colors.lime)
    print("CA installed as root of trust!")
    term.setTextColor(colors.white)
    print()
    print("The CA key remains on the floppy disk.")
    print("Keep the disk safe - you need it to sign files with 'pki-sign'.")
    print("Trust takes effect on next boot.")
    print()
else
    term.setTextColor(colors.red)
    printError("Failed to install CA.")
    term.setTextColor(colors.white)
    if result then print(tostring(result)) end
end
