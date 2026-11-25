import io.agenticcontrol.app.rmmspine.ManagementPolicyDocument
import io.agenticcontrol.app.rmmspine.ManagementPolicyEngine
import io.agenticcontrol.app.rmmspine.PolicyGate
import io.agenticcontrol.app.rmmspine.PolicyLevels
import io.agenticcontrol.app.rmmspine.StaticDeviceFacts
import io.agenticcontrol.app.transport.TorArtefact
import io.agenticcontrol.app.transport.TorComponentFile
import io.agenticcontrol.app.transport.TorComponentManifest
import io.agenticcontrol.app.transport.TorPins
import io.agenticcontrol.app.transport.TorProcessRunner
import io.agenticcontrol.app.transport.TorProvisioner
import io.agenticcontrol.app.transport.TorSetupService
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/**
 * A2 (Android mirror): Tor binary provisioning — production pin
 * state, manifest integrity, fixture provisioning against a
 * locally produced stand-in artefact, and the destruction cases:
 * a tampered binary fails verification and is NEVER executed, a
 * traversal entry in the bundle writes nothing outside the
 * component home, and a downgrade swap of a pinned hash fails
 * the manifest's own integrity digest before any fetch.
 *
 * Socket legs: the setup act's success path waits on a loopback
 * SOCKS greeting; JVM-originated loopback connects are reset in
 * this sandbox (standing fact), so here the setup act is proven
 * on its refusal paths (tampered binary never launches; a proxy
 * that never answers yields the named refusal and no tor.json).
 * The success path is proven by the Windows suite and the live
 * proof artefact (proofs/tor-rung-v1/).
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/** Build a tar.gz stand-in "expert bundle" in memory. */
private fun buildBundle(entries: List<Pair<String, ByteArray>>): ByteArray {
    val out = ByteArrayOutputStream()
    GZIPOutputStream(out).use { gz ->
        for ((name, bytes) in entries) {
            val header = ByteArray(512)
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            nameBytes.copyInto(header, 0, 0, minOf(nameBytes.size, 100))
            val mode = "0000644\u0000".toByteArray(Charsets.UTF_8); mode.copyInto(header, 100)
            val uid = "0000000\u0000".toByteArray(Charsets.UTF_8); uid.copyInto(header, 108); uid.copyInto(header, 116)
            val size = bytes.size.toString(8).padStart(11, '0') + "\u0000"; size.toByteArray(Charsets.UTF_8).copyInto(header, 124)
            val mtime = "00000000000\u0000".toByteArray(Charsets.UTF_8); mtime.copyInto(header, 136)
            header[156] = '0'.code.toByte()
            "ustar\u0000".toByteArray(Charsets.UTF_8).copyInto(header, 257)
            // checksum: spaces during computation
            for (i in 148 until 156) header[i] = ' '.code.toByte()
            var sum = 0; for (b in header) sum += b.toInt() and 0xFF
            val chk = sum.toString(8).padStart(6, '0') + "\u0000 "
            chk.toByteArray(Charsets.UTF_8).copyInto(header, 148)
            gz.write(header)
            gz.write(bytes)
            val pad = (512 - (bytes.size % 512)) % 512
            if (pad > 0) gz.write(ByteArray(pad))
        }
        gz.write(ByteArray(1024))
    }
    return out.toByteArray()
}

private class TorFixture(
    val manifest: TorComponentManifest, val artefact: TorArtefact,
    val bundleBytes: ByteArray, val baseDir: File
)

private fun buildTorFixture(binaryOverride: ByteArray? = null, includeTraversal: Boolean = false): TorFixture {
    val binary = binaryOverride ?: "ACP FIXTURE TOR BINARY — inert stand-in, never executed".toByteArray(Charsets.UTF_8)
    val geoip = "fixture geoip".toByteArray(Charsets.UTF_8)
    val entries = mutableListOf(
        "tor/libTor.so" to binary,
        "data/geoip" to geoip,
        "docs/readme.txt" to "unpinned bundle member — must be ignored".toByteArray(Charsets.UTF_8)
    )
    if (includeTraversal) entries.add("../../evil.so" to "traversal payload".toByteArray(Charsets.UTF_8))
    val bundleBytes = buildBundle(entries)
    val files = listOf(
        TorComponentFile("tor/libTor.so", sha256Hex(binary), binary.size.toLong()),
        TorComponentFile("data/geoip", sha256Hex(geoip), geoip.size.toLong())
    )
    val artefact = TorArtefact("fixture-platform", "fixture-bundle.tar.gz",
        sha256Hex(bundleBytes), bundleBytes.size.toLong(), "tor/libTor.so", files)
    val manifest = TorComponentManifest.forFixture("fixture://local", artefact)
    val baseDir = Files.createTempDirectory("acp-tor-test").toFile()
    return TorFixture(manifest, artefact, bundleBytes, baseDir)
}

private class FakeTorProcess : TorProcessRunner {
    var startCount = 0
    override var isRunning = false
    override fun start(binaryPath: File, torrcPath: File, workingDir: File) { startCount++; isRunning = true }
    override fun stop() { isRunning = false }
}

fun main() {
    // ---- production pins -------------------------------------------------
    val prod = TorComponentManifest.PRODUCTION
    check("torpins: bundle version pinned", prod.bundleVersion == "16.0.1")
    check("torpins: tor version pinned", prod.torVersion == "0.4.9.16")
    check("torpins: three artefacts", prod.artefacts.size == 3)
    val integrity = prod.validateIntegrity()
    check("torpins: production manifest integrity valid (${integrity.second})", integrity.first)
    check("torpins: digest recomputes",
        TorComponentManifest.computeManifestDigest(prod.bundleVersion, prod.downloadBaseUrl, prod.artefacts) == prod.manifestDigest)
    check("torpins: windows bundle pin",
        prod.forPlatform(TorPins.WINDOWS_X64)?.bundleSha256 == "9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b")
    check("torpins: android bundle pin",
        prod.forPlatform(TorPins.ANDROID_ARM64)?.bundleSha256 == "0091927b9fd72992a88021d55416b23a8380dc39a70c4b73a2cca9ee6a3dbcec")
    check("torpins: android binary is libTor.so",
        prod.forPlatform(TorPins.ANDROID_ARM64)?.binaryBundlePath == "tor/libTor.so")

    // ---- fixture provisioning -------------------------------------------
    run {
        val fx = buildTorFixture()
        val home = File(fx.baseDir, "tor")
        val prov = TorProvisioner(fx.manifest)
        val result = prov.provision(home, fx.artefact, { _, dest -> dest.writeBytes(fx.bundleBytes) }, fixtureMode = true)
        check("torprovision: fixture installs (${result.second})", result.first)
        check("torprovision: binary landed", File(home, "tor/libTor.so").exists())
        check("torprovision: geoip landed", File(home, "data/geoip").exists())
        check("torprovision: unpinned member never lands", !File(home, "docs/readme.txt").exists())
        check("torprovision: install record written", File(home, TorProvisioner.INSTALL_RECORD_FILE_NAME).exists())
        check("torprovision: installed verifies", prov.verifyInstalled(home, fx.artefact).first)
        fx.baseDir.deleteRecursively()
    }

    run {
        val fx = buildTorFixture()
        val tampered = fx.bundleBytes.copyOf()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0xFF).toByte()
        val home = File(fx.baseDir, "tor")
        val prov = TorProvisioner(fx.manifest)
        val result = prov.provision(home, fx.artefact, { _, dest -> dest.writeBytes(tampered) }, fixtureMode = true)
        check("torprovision: tampered bundle refused", !result.first && result.second.contains("HASH MISMATCH"))
        check("torprovision: tampered bundle installs nothing", !File(home, "tor/libTor.so").exists())
        fx.baseDir.deleteRecursively()
    }

    run {
        val fx = buildTorFixture(includeTraversal = true)
        val home = File(fx.baseDir, "tor")
        val prov = TorProvisioner(fx.manifest)
        val result = prov.provision(home, fx.artefact, { _, dest -> dest.writeBytes(fx.bundleBytes) }, fixtureMode = true)
        check("torprovision: traversal bundle still provisions pinned files (${result.second})", result.first)
        check("torprovision: traversal payload written nowhere outside home",
            !File(fx.baseDir, "evil.so").exists() && !File(fx.baseDir.parentFile, "evil.so").exists())
        fx.baseDir.deleteRecursively()
    }

    run {
        val fx = buildTorFixture()
        val swapped = fx.artefact.copy(bundleSha256 = sha256Hex("attacker bundle".toByteArray(Charsets.UTF_8)))
        val manifest = fx.manifest.copy(artefacts = listOf(swapped))
        check("torprovision: downgrade swap fails manifest integrity", !manifest.validateIntegrity().first)
        var fetched = false
        val prov = TorProvisioner(manifest)
        val result = prov.provision(File(fx.baseDir, "tor"), swapped, { _, _ -> fetched = true }, fixtureMode = true)
        check("torprovision: downgrade swap refused before fetch", !result.first && !fetched)
        fx.baseDir.deleteRecursively()
    }

    run {
        val fx = buildTorFixture()
        val prov = TorProvisioner(fx.manifest)
        val result = prov.provision(File(fx.baseDir, "tor"), fx.artefact,
            { _, dest -> dest.writeBytes(fx.bundleBytes) },
            sourceBaseOverride = "https://mirror.example/tor", fixtureMode = false)
        check("torprovision: production source override refused", !result.first && result.second.contains("wrong source"))
        fx.baseDir.deleteRecursively()
    }

    // ---- setup act --------------------------------------------------------
    run {
        val fx = buildTorFixture()
        val home = File(fx.baseDir, "tor")
        val dataDir = File(fx.baseDir, "data")
        val prov = TorProvisioner(fx.manifest)
        val provisioned = prov.provision(home, fx.artefact, { _, dest -> dest.writeBytes(fx.bundleBytes) }, fixtureMode = true)
        check("torsetup: fixture provisioned for tamper test", provisioned.first)
        val binary = File(home, "tor/libTor.so")
        val bytes = binary.readBytes(); bytes[0] = (bytes[0].toInt() xor 0xFF).toByte(); binary.writeBytes(bytes)
        val fake = FakeTorProcess()
        val setup = TorSetupService(prov, fake, home, dataDir)
        val result = setup.runSetup({ _, dest -> dest.writeBytes(fx.bundleBytes) }, fixtureMode = true, platform = "fixture-platform")
        check("torsetup: tampered binary refused (${result.second})", !result.first && result.second.contains("HASH MISMATCH"))
        check("torsetup: tampered binary NEVER executed", fake.startCount == 0)
        check("torsetup: no tor.json written on refusal", !File(dataDir, "tor.json").exists())
        fx.baseDir.deleteRecursively()
    }

    run {
        val fx = buildTorFixture()
        val home = File(fx.baseDir, "tor")
        val dataDir = File(fx.baseDir, "data")
        val fake = FakeTorProcess() // "starts" but opens no SOCKS listener
        val setup = TorSetupService(TorProvisioner(fx.manifest), fake, home, dataDir)
        val result = setup.runSetup({ _, dest -> dest.writeBytes(fx.bundleBytes) },
            fixtureMode = true, platform = "fixture-platform", socksWaitMs = 750)
        check("torsetup: silent proxy named refusal (${result.second})",
            !result.first && result.second.contains("did not open its local SOCKS listener"))
        check("torsetup: no tor.json on proxy-down", !File(dataDir, "tor.json").exists())
        check("torsetup: dead client stopped", !fake.isRunning)
        fx.baseDir.deleteRecursively()
    }

    run {
        // W20 (W19-C parity): the setup act is gated on
        // rmm.tor_provisioning.enabled; a stop is never gated.
        val fx = buildTorFixture()
        val home = File(fx.baseDir, "tor")
        val dataDir = File(fx.baseDir, "data")
        val engine = ManagementPolicyEngine()
        engine.addDocument(ManagementPolicyDocument("w20-tor", PolicyLevels.ORG, "co",
            mapOf("rmm.tor_provisioning.enabled" to "false"), 1))
        PolicyGate.bind(engine, StaticDeviceFacts("phone-1", "co"))
        try {
            val fake = FakeTorProcess()
            val setup = TorSetupService(TorProvisioner(fx.manifest), fake, home, dataDir)
            val result = setup.runSetup({ _, dest -> dest.writeBytes(fx.bundleBytes) },
                fixtureMode = true, platform = "fixture-platform")
            check("torsetup W20: policy OFF refuses the setup act by name (${result.second})",
                !result.first && result.second.contains("rmm.tor_provisioning.enabled"))
            check("torsetup W20: policy OFF never provisions or launches",
                fake.startCount == 0 && !File(home, "tor/libTor.so").exists())
            dataDir.mkdirs(); File(dataDir, "tor.json").writeText("{}")
            setup.stopAndUnconfigure()
            check("torsetup W20: stop/unconfigure stays available under policy OFF (a stop is never policy-gated)",
                !File(dataDir, "tor.json").exists())
        } finally {
            PolicyGate.unbind()
        }
        fx.baseDir.deleteRecursively()
    }

    run {
        val home = File(Files.createTempDirectory("acp-tor-torrc").toFile(), "tor")
        val torrc = TorSetupService.buildTorrc(home, TorPins.SOCKS_PORT)
        check("torsetup: torrc is local-only socks", torrc.contains("SocksPort 127.0.0.1:${TorPins.SOCKS_PORT}"))
        check("torsetup: torrc has no control/or port", !torrc.contains("ControlPort") && !torrc.contains("ORPort"))
        // readTorConfig round-trip on the exact shape the act writes
        val dataDir = Files.createTempDirectory("acp-tor-cfg").toFile()
        File(dataDir, "tor.json").writeText("{\"socksHost\":\"127.0.0.1\",\"socksPort\":${TorPins.SOCKS_PORT}}")
        val cfg = TorSetupService.readTorConfig(dataDir)
        check("torsetup: tor.json readable as rung config", cfg != null && cfg.socksHost == "127.0.0.1" && cfg.socksPort == TorPins.SOCKS_PORT)
        check("torsetup: missing tor.json = unconfigured", TorSetupService.readTorConfig(File(dataDir, "nope")) == null)
    }

    println(if (failures == 0) "TorProvisioningTest: ALL PASS" else "TorProvisioningTest: $failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
