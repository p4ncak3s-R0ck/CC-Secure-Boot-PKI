local ok, err = pcall(function()
    local pki = require "pki"
    local container = require "cert.container"
    local chain = require "cert.chain"

    local ok, roots = pcall(pki.getComputerRoots)
    if not ok or not roots or #roots == 0 then return end

    local extraRoots = {}
    for _, certPem in ipairs(roots) do
        local ok, der, typ = pcall(container.decodePEM, certPem)
        if ok and typ == "CERTIFICATE" then
            local ok, c = pcall(container.loadX509, der)
            if ok then extraRoots[#extraRoots + 1] = c end
        end
    end

    if #extraRoots == 0 then return end

    local oldValidate = chain.validate
    chain.validate = function(cert, certList, rootPath, additionalRoots)
        local combined = {}
        for _, v in ipairs(extraRoots) do combined[#combined + 1] = v end
        if additionalRoots then
            for _, v in ipairs(additionalRoots) do combined[#combined + 1] = v end
        end
        local filtered = {}
        for _, c in ipairs(certList) do
            local ok1, sub = pcall(tostring, c.subject)
            local ok2, iss = pcall(tostring, c.issuer)
            if not (ok1 and ok2 and sub == iss) then
                filtered[#filtered + 1] = c
            end
        end
        return oldValidate(cert, #filtered > 0 and filtered or certList, rootPath, combined)
    end
end)
