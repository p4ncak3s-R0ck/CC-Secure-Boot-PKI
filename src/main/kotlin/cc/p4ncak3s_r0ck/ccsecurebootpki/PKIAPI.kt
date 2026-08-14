package cc.p4ncak3s_r0ck.ccsecurebootpki

import dan200.computercraft.api.lua.IComputerSystem
import dan200.computercraft.api.lua.ILuaAPI
import dan200.computercraft.api.lua.LuaException
import dan200.computercraft.api.lua.LuaFunction
import dan200.computercraft.api.lua.MethodResult
import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.SignerInfoGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.lang.reflect.Field
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.stream.Stream

class PKIAPI(private val computer: IComputerSystem) : ILuaAPI {

    private var worldFolder: Path? = null

    override fun getNames(): Array<String> = emptyArray<String>()

    override fun getModuleName(): String = "pki"

    @LuaFunction
    fun generateCA(parameters: Map<String, String>, expiryTime: Date): Map<String, ByteBuffer> {
        val now: Date = Date()

        val dname: String = parameters.entries.joinToString(",") { entry: Map.Entry<String, String> ->
            "${entry.key}=${entry.value}"
        }

        val keyPair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val subject: X500Name = X500Name(dname)
        val serial: ByteArray = ByteArray(32).also { bytes: ByteArray ->
            SecureRandom.getInstanceStrong().nextBytes(bytes)
        }

        val builder: JcaX509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger(serial),
            now,
            expiryTime,
            subject,
            keyPair.public
        )
        val signer: ContentSigner = JcaContentSignerBuilder("Ed25519").build(keyPair.private)
        val holder: X509CertificateHolder = builder.build(signer)
        val cert: X509Certificate = JcaX509CertificateConverter().getCertificate(holder)

        val keyPem: ByteArray = ByteArrayOutputStream().use { out: ByteArrayOutputStream ->
            PemWriter(OutputStreamWriter(out)).use { pw: PemWriter ->
                pw.writeObject(PemObject("PRIVATE KEY", keyPair.private.encoded))
            }
            out.toByteArray()
        }

        val certPem: ByteArray = ByteArrayOutputStream().use { out: ByteArrayOutputStream ->
            PemWriter(OutputStreamWriter(out)).use { pw: PemWriter ->
                pw.writeObject(PemObject("CERTIFICATE", cert.encoded))
            }
            out.toByteArray()
        }

        return mapOf<String, ByteBuffer>(
            "key" to ByteBuffer.wrap(keyPem),
            "cert" to ByteBuffer.wrap(certPem)
        )
    }

    @LuaFunction
    fun sign(keyPem: ByteBuffer, certPem: ByteBuffer, data: ByteBuffer): ByteBuffer {
        val keyBytes: ByteArray = drain(keyPem)
        val certBytes: ByteArray = drain(certPem)
        val dataBytes: ByteArray = drain(data)

        val keyReader: PemReader = PemReader(InputStreamReader(ByteArrayInputStream(keyBytes)))
        val keyObj: PemObject = keyReader.readPemObject()
        keyReader.close()

        val kf: KeyFactory = KeyFactory.getInstance("Ed25519")
        val privateKey: PrivateKey = kf.generatePrivate(PKCS8EncodedKeySpec(keyObj.content))

        val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
        val cert: X509Certificate = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

        val gen: CMSSignedDataGenerator = CMSSignedDataGenerator()
        val signer: ContentSigner = JcaContentSignerBuilder("Ed25519").build(privateKey)
        val digestCalc: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().build()
        val signerInfo: SignerInfoGenerator = JcaSignerInfoGeneratorBuilder(digestCalc).build(signer, cert)
        gen.addSignerInfoGenerator(signerInfo)

        val cmsData: CMSProcessableByteArray = CMSProcessableByteArray(dataBytes)
        val signedData: CMSSignedData = gen.generate(cmsData, false)
        return ByteBuffer.wrap(signedData.encoded)
    }

    @LuaFunction
    fun installCA(certPem: ByteBuffer): MethodResult {
        return try {
            val certBytes: ByteArray = drain(certPem)
            val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
            val cert: X509Certificate = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            cert.verify(cert.publicKey)

            val server: MinecraftServer = computer.level.server
                ?: return MethodResult.of(false, "Server not available")
            val dir: Path = getWorldFolder(server)

            val cn: String = cert.subjectX500Principal.name
                .split(",")
                .firstOrNull { component: String -> component.trimStart().startsWith("CN=") }
                ?.substringAfter("CN=")
                ?.trim()
                ?: "ca"
            val safeName: String = cn.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)

            val rootDir: Path = dir.resolve("certs")
            Files.createDirectories(rootDir)
            PemWriter(OutputStreamWriter(Files.newOutputStream(rootDir.resolve("root.pem")))).use { w: PemWriter ->
                w.writeObject(PemObject("CERTIFICATE", cert.encoded))
            }

            val compDir: Path = dir.resolve("certs/computer-${computer.id}")
            Files.createDirectories(compDir)
            PemWriter(OutputStreamWriter(Files.newOutputStream(compDir.resolve("$safeName.pem")))).use { w: PemWriter ->
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
            val server: MinecraftServer = computer.level.server ?: return null
            val dir: Path = getWorldFolder(server).resolve("certs/computer-${computer.id}")
            if (!Files.isDirectory(dir)) return null

            val certs: MutableList<ByteBuffer> = mutableListOf<ByteBuffer>()
            Files.list(dir).use { stream: Stream<Path> ->
                stream
                    .filter { path: Path -> path.toString().endsWith(".pem") }
                    .forEach { path: Path ->
                        certs.add(ByteBuffer.wrap(Files.readAllBytes(path)))
                    }
            }

            if (certs.isEmpty()) null else certs
        } catch (_: Exception) {
            null
        }
    }

    @LuaFunction
    fun getInstalledCAs(): List<Map<String, Any?>>? {
        return try {
            val server: MinecraftServer = computer.level.server ?: return null
            val dir: Path = getWorldFolder(server).resolve("certs/computer-${computer.id}")
            if (!Files.isDirectory(dir)) return null

            val result: MutableList<Map<String, Any?>> = mutableListOf<Map<String, Any?>>()
            Files.list(dir).use { stream: Stream<Path> ->
                stream
                    .filter { path: Path -> path.toString().endsWith(".pem") }
                    .forEach { path: Path ->
                        try {
                            val pemBytes: ByteArray = Files.readAllBytes(path)
                            val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
                            val cert: X509Certificate = cf.generateCertificate(ByteArrayInputStream(pemBytes)) as X509Certificate
                            val cn: String = cert.subjectX500Principal.name
                                .split(",")
                                .firstOrNull { component: String -> component.trimStart().startsWith("CN=") }
                                ?.substringAfter("CN=")
                                ?.trim()
                                ?: "Unknown"

                            val caInfo: Map<String, Any?> = mapOf<String, Any?>(
                                "name" to cn,
                                "subject" to cert.subjectX500Principal.name,
                                "pem" to ByteBuffer.wrap(pemBytes)
                            )
                            result.add(caInfo)
                        } catch (_: Exception) {
                        }
                    }
            }

            if (result.isEmpty()) null else result
        } catch (_: Exception) {
            null
        }
    }

    @LuaFunction
    fun uninstallCA(certPem: ByteBuffer): MethodResult {
        return try {
            val certBytes: ByteArray = drain(certPem)
            val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
            val cert: X509Certificate = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            val server: MinecraftServer = computer.level.server
                ?: return MethodResult.of(false, "Server not available")
            val dir: Path = getWorldFolder(server)

            val cn: String = cert.subjectX500Principal.name
                .split(",")
                .firstOrNull { component: String -> component.trimStart().startsWith("CN=") }
                ?.substringAfter("CN=")
                ?.trim()
                ?: "ca"
            val safeName: String = cn.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)

            val compFile: Path = dir.resolve("certs/computer-${computer.id}/$safeName.pem")
            if (Files.exists(compFile)) {
                Files.delete(compFile)
            }

            val rootFile: Path = dir.resolve("certs/root.pem")
            if (Files.exists(rootFile)) {
                val rootBytes: ByteArray = Files.readAllBytes(rootFile)
                if (rootBytes.contentEquals(cert.encoded)) {
                    Files.delete(rootFile)
                    val keyFile: Path = dir.resolve("root.key")
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
            val server: MinecraftServer = computer.level.server ?: return null
            val dir: Path = getWorldFolder(server)
            val keyFile: Path = dir.resolve("root.key")
            val certFile: Path = dir.resolve("certs/root.pem")
            if (Files.notExists(keyFile) || Files.notExists(certFile)) return null

            mapOf<String, Any?>(
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
        val server: MinecraftServer = computer.level.server
            ?: throw LuaException("Server not available")
        val dir: Path = getWorldFolder(server)
        val rootExists: Boolean = Files.exists(dir.resolve("certs/root.pem"))
        val enrolledDir: Path = dir.resolve("certs/enrolled")
        val enrolled: Int = if (Files.exists(enrolledDir)) {
            enrolledDir.toFile().list()?.size ?: 0
        } else {
            0
        }
        val thisEnrolled: Boolean = Files.exists(enrolledDir.resolve(computer.id.toString()))

        return mapOf<String, Any?>(
            "rootInstalled" to rootExists,
            "enrolledComputers" to enrolled,
            "thisComputerEnrolled" to thisEnrolled,
            "worldPath" to dir.toString()
        )
    }

    private fun drain(buf: ByteBuffer): ByteArray {
        val out: ByteArray = ByteArray(buf.remaining())
        buf.get(out)
        return out
    }

    private fun getWorldFolder(server: MinecraftServer): Path {
        val cached: Path? = worldFolder
        if (cached != null) return cached

        val ctxClass: Class<*> = Class.forName("dan200.computercraft.shared.computer.core.ServerContext")
        val field: Field = ctxClass.getDeclaredField("FOLDER").also { declaredField: Field ->
            declaredField.isAccessible = true
        }
        val resource: LevelResource = field.get(null) as LevelResource
        val path: Path = server.getWorldPath(resource)
        worldFolder = path
        return path
    }
}