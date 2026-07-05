package cc.p4ncak3s_r0ck.ccsecurebootpki

import dan200.computercraft.api.ComputerCraftAPI
import dan200.computercraft.api.lua.IComputerSystem
import dan200.computercraft.api.lua.ILuaAPI
import dan200.computercraft.api.lua.ILuaAPIFactory
import net.neoforged.fml.common.Mod
import org.apache.logging.log4j.LogManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jspecify.annotations.Nullable
import java.security.Security

@Mod(CCSecureBootPKI.MOD_ID)
class CCSecureBootPKI : ILuaAPIFactory {
    companion object {
        const val MOD_ID = "ccsecurebootpki"
        val LOG = LogManager.getLogger(MOD_ID)
    }

    init {
        Security.addProvider(BouncyCastleProvider())
        ComputerCraftAPI.registerAPIFactory(this)
        LOG.info("CCSecureBoot PKI addon initialized")
    }

    override fun create(computer: IComputerSystem): @Nullable ILuaAPI {
        return PKIAPI(computer)
    }
}
