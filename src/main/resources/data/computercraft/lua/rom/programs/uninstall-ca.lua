local pki = require "pki"

print("=== Uninstall Certificate Authority ===")

local ok, caList = pcall(pki.getInstalledCAs)
if not ok or not caList or #caList == 0 then
    printError("No CAs are installed on this computer.")
    print("Run 'install-ca' to install a CA first.")
    return
end

print("Installed Certificate Authorities:")
print()
for i, ca in ipairs(caList) do
    print("  [" .. i .. "] " .. ca.name)
    print("      " .. ca.subject)
    print()
end

write("Select a CA to uninstall (or press Enter to cancel): ")
local choice = read()
if choice == "" then
    print("Cancelled.")
    return
end

local idx = tonumber(choice)
if not idx or idx < 1 or idx > #caList then
    printError("Invalid selection.")
    return
end

local selected = caList[idx]

term.setTextColor(colors.yellow)
print("WARNING: This will remove '" .. selected.name .. "' from the trust store.")
print("Computers enrolled with this CA will no longer boot unless another CA is installed.")
term.setTextColor(colors.white)
write("Are you sure? [y/N] ")
local confirm = read()
if confirm:lower() ~= "y" and confirm:lower() ~= "yes" then
    print("Cancelled.")
    return
end

print("Uninstalling CA...")
local ok, result = pcall(pki.uninstallCA, selected.pem)
if not ok then
    printError("Failed to uninstall CA: " .. tostring(result))
    return
end

if result then
    term.setTextColor(colors.lime)
    print("CA '" .. selected.name .. "' uninstalled!")
    term.setTextColor(colors.white)
    print()
    print("The CA is no longer trusted by this computer.")
    print("If this was the world root, the server will generate")
    print("a fresh auto-generated root on next restart.")
    print()
else
    term.setTextColor(colors.red)
    printError("Failed to uninstall CA.")
    term.setTextColor(colors.white)
end
