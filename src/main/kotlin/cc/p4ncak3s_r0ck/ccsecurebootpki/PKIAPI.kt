package cc.p4ncak3s_r0ck.ccsecurebootpki

import dan200.computercraft.api.lua.IComputerSystem
import dan200.computercraft.api.lua.ILuaAPI
import dan200.computercraft.api.lua.LuaException
import dan200.computercraft.api.lua.LuaFunction
import dan200.computercraft.api.lua.MethodResult
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date

class PKIAPI(private val computer: IComputerSystem) : ILuaAPI {

    private var worldFolder: Path? = null

    override fun getNames(): Array<String> = emptyArray()

    override fun getModuleName(): String = "pki"

    @LuaFunction
    fun generateCA(name: String): Map<String, ByteBuffer> {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val subject = X500Name("CN=$name")
        val serial = ByteArray(32).also { SecureRandom.getInstanceStrong().nextBytes(it) }
        val now = Date()
        val expiry = Date(System.currentTimeMillis() + 30L * 365 * 24 * 60 * 60 * 1000)

        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger(serial), now, expiry, subject, keyPair.public
        )
        val signer = JcaContentSignerBuilder("Ed25519").build(keyPair.private)
        val holder = builder.build(signer)
        val cert = JcaX509CertificateConverter().getCertificate(holder)

        val keyPem = ByteArrayOutputStream().use { out ->
            PemWriter(OutputStreamWriter(out)).use { pw ->
                pw.writeObject(PemObject("PRIVATE KEY", keyPair.private.encoded))
            }
            out.toByteArray()
        }
        val certPem = ByteArrayOutputStream().use { out ->
            PemWriter(OutputStreamWriter(out)).use { pw ->
                pw.writeObject(PemObject("CERTIFICATE", cert.encoded))
            }
            out.toByteArray()
        }
        return mapOf("key" to ByteBuffer.wrap(keyPem), "cert" to ByteBuffer.wrap(certPem))
    }

    @LuaFunction
    fun sign(keyPem: ByteBuffer, certPem: ByteBuffer, data: ByteBuffer): ByteBuffer {
        val keyBytes = drain(keyPem)
        val certBytes = drain(certPem)
        val dataBytes = drain(data)

        val keyReader = PemReader(InputStreamReader(ByteArrayInputStream(keyBytes)))
        val keyObj = keyReader.readPemObject()
        keyReader.close()
        val kf = KeyFactory.getInstance("Ed25519")
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(keyObj.content))

        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

        val gen = CMSSignedDataGenerator()
        val signer = JcaContentSignerBuilder("Ed25519").build(privateKey)
        val digestCalc = JcaDigestCalculatorProviderBuilder().build()
        val signerInfo = JcaSignerInfoGeneratorBuilder(digestCalc).build(signer, cert)
        gen.addSignerInfoGenerator(signerInfo)

        val cmsData = CMSProcessableByteArray(dataBytes)
        val signedData = gen.generate(cmsData, false)
        return ByteBuffer.wrap(signedData.encoded)
    }

    @LuaFunction
    fun installCA(certPem: ByteBuffer): MethodResult {
        return try {
            val certBytes = drain(certPem)
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            cert.verify(cert.publicKey)

            val server = computer.level.server ?: return MethodResult.of(false, "Server not available")
            val dir = getWorldFolder(server)

            val cn = cert.subjectX500Principal.name
                .split(",").firstOrNull { it.trimStart().startsWith("CN=") }
                ?.substringAfter("CN=")?.trim()
                ?: "ca"
            val safeName = cn.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)

            val rootDir = dir.resolve("certs")
            Files.createDirectories(rootDir)
            PemWriter(OutputStreamWriter(Files.newOutputStream(rootDir.resolve("root.pem")))).use { w ->
                w.writeObject(PemObject("CERTIFICATE", cert.encoded))
            }

            val compDir = dir.resolve("certs/computer-${computer.id}")
            Files.createDirectories(compDir)
            PemWriter(OutputStreamWriter(Files.newOutputStream(compDir.resolve("$safeName.pem")))).use { w ->
                w.writeObject(PemObject("CERTIFICATE", cert.encoded))
            }

            CCSecureBootPKI.LOG.info("CA certificate '{}' installed as root of trust", cn)
            MethodResult.of(true)
        } catch (e: Exception) {
            CCSecureBootPKI.LOG.error("installCA failed", e)
            MethodResult.of(false, e.message)
        }
    }

    @LuaFunction
    fun getComputerRoots(): List<ByteBuffer>? {
        return try {
            val server = computer.level.server ?: return null
            val dir = getWorldFolder(server).resolve("certs/computer-${computer.id}")
            if (!Files.isDirectory(dir)) return null

            val certs = mutableListOf<ByteBuffer>()
            Files.list(dir).use { stream ->
                stream.filter { it.toString().endsWith(".pem") }.forEach { path ->
                    certs.add(ByteBuffer.wrap(Files.readAllBytes(path)))
                }
            }
            certs.ifEmpty { null }
        } catch (_: Exception) {
            null
        }
    }

    @LuaFunction
    fun getInstalledCAs(): List<Map<String, Any?>>? {
        return try {
            val server = computer.level.server ?: return null
            val dir = getWorldFolder(server).resolve("certs/computer-${computer.id}")
            if (!Files.isDirectory(dir)) return null

            val result = mutableListOf<Map<String, Any?>>()
            Files.list(dir).use { stream ->
                stream.filter { it.toString().endsWith(".pem") }.forEach { path ->
                    try {
                        val pemBytes = Files.readAllBytes(path)
                        val cf = CertificateFactory.getInstance("X.509")
                        val cert = cf.generateCertificate(ByteArrayInputStream(pemBytes)) as X509Certificate
                        val cn = cert.subjectX500Principal.name
                            .split(",").firstOrNull { it.trimStart().startsWith("CN=") }
                            ?.substringAfter("CN=")?.trim()
                            ?: "Unknown"
                        result.add(mapOf(
                            "name" to cn,
                            "subject" to cert.subjectX500Principal.name,
                            "pem" to ByteBuffer.wrap(pemBytes)
                        ))
                    } catch (_: Exception) { }
                }
            }
            result.ifEmpty { null }
        } catch (_: Exception) {
            null
        }
    }

    @LuaFunction
    fun uninstallCA(certPem: ByteBuffer): MethodResult {
        return try {
            val certBytes = drain(certPem)
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            val server = computer.level.server ?: return MethodResult.of(false, "Server not available")
            val dir = getWorldFolder(server)

            val cn = cert.subjectX500Principal.name
                .split(",").firstOrNull { it.trimStart().startsWith("CN=") }
                ?.substringAfter("CN=")?.trim()
                ?: "ca"
            val safeName = cn.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)

            val compFile = dir.resolve("certs/computer-${computer.id}/$safeName.pem")
            if (Files.exists(compFile)) {
                Files.delete(compFile)
            }

            val rootFile = dir.resolve("certs/root.pem")
            if (Files.exists(rootFile)) {
                val rootBytes = Files.readAllBytes(rootFile)
                if (rootBytes.contentEquals(cert.encoded)) {
                    Files.delete(rootFile)
                    val keyFile = dir.resolve("root.key")
                    if (Files.exists(keyFile)) {
                        Files.delete(keyFile)
                    }
                }
            }

            CCSecureBootPKI.LOG.info("CA certificate '{}' uninstalled", cn)
            MethodResult.of(true)
        } catch (e: Exception) {
            CCSecureBootPKI.LOG.error("uninstallCA failed", e)
            MethodResult.of(false, e.message)
        }
    }

    @LuaFunction
    fun exportRoot(): Map<String, Any?>? {
        return try {
            val server = computer.level.server ?: return null
            val dir = getWorldFolder(server)
            val keyFile = dir.resolve("root.key")
            val certFile = dir.resolve("certs/root.pem")
            if (Files.notExists(keyFile) || Files.notExists(certFile)) return null
            mapOf(
                "key" to ByteBuffer.wrap(Files.readAllBytes(keyFile)),
                "cert" to ByteBuffer.wrap(Files.readAllBytes(certFile))
            )
        } catch (_: Exception) {
            null
        }
    }

    @LuaFunction
    @Throws(LuaException::class)
    fun getStatus(): Map<String, Any?> {
        val server = computer.level.server
        val dir = getWorldFolder(server)
        val rootExists = dir.let { Files.exists(it.resolve("certs/root.pem")) } ?: false
        val enrolledDir = dir.resolve("certs/enrolled")
        val enrolled = enrolledDir?.let { if (Files.exists(it)) it.toFile().list()?.size ?: 0 else 0 } ?: 0
        val thisEnrolled = enrolledDir?.let { Files.exists(it.resolve(computer.id.toString())) } ?: false

        return mapOf(
            "rootInstalled" to rootExists,
            "enrolledComputers" to enrolled,
            "thisComputerEnrolled" to thisEnrolled,
            "worldPath" to (dir?.toString() ?: "unknown")
        )
    }

    private fun drain(buf: ByteBuffer): ByteArray {
        val out = ByteArray(buf.remaining())
        buf.get(out)
        return out
    }

    private fun getWorldFolder(server: net.minecraft.server.MinecraftServer): Path {
        val cached = worldFolder
        if (cached != null) return cached

        val ctxClass = Class.forName("dan200.computercraft.shared.computer.core.ServerContext")
        val field = ctxClass.getDeclaredField("FOLDER").also { it.isAccessible = true }
        val resource = field.get(null) as net.minecraft.world.level.storage.LevelResource
        val path = server.getWorldPath(resource)
        worldFolder = path
        return path
    }
}
