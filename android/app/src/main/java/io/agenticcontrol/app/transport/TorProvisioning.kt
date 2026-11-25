package io.agenticcontrol.app.transport

import io.agenticcontrol.app.rmmspine.PolicyGate
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/**
 * Tor component provisioning (A2, 2026-11-22) — Android mirror of
 * the Windows Acp.Shared.Tor machinery. Until this block, the
 * `tor` rung worked only if a SOCKS proxy appeared by means
 * outside ACP: no Tor binary was pinned, bundled, or provisioned
 * by any setup flow. This file is that flow, built to the
 * product's verified-download discipline (the AiPack discipline
 * and the hub-component pin precedent):
 *
 *  * The genuine Tor artefact is the Tor Project's OWN expert
 *    bundle, pinned the way Headscale is pinned: bundle version +
 *    tor version + SHA-256 of the bundle AND of every file ACP
 *    installs from it, in windows-agent/tor-component/
 *    PACKAGE-MANIFEST.md and in code ([TorPins] / the production
 *    manifest below).
 *  * The bundle pins were captured 2026-11-22 from the author's
 *    own published sha256sums for Tor Browser 16.0.1
 *    (dist.torproject.org); every bundle was downloaded and
 *    hash-verified against those sums before its contents were
 *    pinned, and the extracted binaries were hashed from the
 *    verified bundles. Capture record:
 *    windows-agent/proofs/tor-rung-v1/capture-record.md.
 *  * The manifest carries an integrity digest over its own pin
 *    list (identical canonical form to Windows): a pin edited to
 *    match a tampered artefact — a downgrade swap — fails
 *    [TorComponentManifest.validateIntegrity] and provisioning
 *    refuses BEFORE any fetch.
 *  * Provisioning verifies size + SHA-256 of the downloaded
 *    bundle, then extracts ONLY the pinned files, each verified
 *    against its own pin before it lands. Tar entry names are
 *    never used as filesystem paths. Any mismatch refuses
 *    totally: partials deleted, nothing installed, NO override.
 *  * The setup act ([TorSetupService]) is the ONLY writer of the
 *    tor.json the rung's configuration is read from. It
 *    re-verifies the installed binary against its pin
 *    immediately before EVERY launch — a tampered binary fails
 *    verification and is never executed.
 *  * The launched client is local-only by construction: the
 *    generated torrc opens exactly one listener, a SOCKS port
 *    bound to 127.0.0.1. No control port, no OR port.
 *
 * Audit status (D37): the Tor client is an adopted component,
 * UNAUDITED in the audit universe; recorded as such here.
 */

/** One file ACP installs from the expert bundle: its path inside
 *  the bundle (also its path under the component home), the
 *  pinned SHA-256 of its bytes, and its pinned size. */
data class TorComponentFile(val bundlePath: String, val sha256: String, val sizeBytes: Long)

/** The pinned expert-bundle artefact for one platform. */
data class TorArtefact(
    val platform: String,
    val bundleFileName: String,
    val bundleSha256: String,
    val bundleSizeBytes: Long,
    val binaryBundlePath: String,
    val files: List<TorComponentFile>
)

object TorPins {
    const val BUNDLE_VERSION = "16.0.1"
    const val TOR_VERSION = "0.4.9.16"
    const val DOWNLOAD_BASE_URL = "https://dist.torproject.org/torbrowser/16.0.1"
    const val WINDOWS_X64 = "windows-x86_64"
    const val ANDROID_ARM64 = "android-aarch64"
    const val LINUX_X64 = "linux-x86_64"

    /** The ACP-managed Tor client's SOCKS port — deliberately not
     *  Tor's 9050 or Tor Browser's 9150; ACP never speaks through
     *  a proxy it did not provision and verify. */
    const val SOCKS_PORT = 9160
    const val SOCKS_HOST = "127.0.0.1"
}

data class TorComponentManifest(
    val bundleVersion: String,
    val torVersion: String,
    val downloadBaseUrl: String,
    val artefacts: List<TorArtefact>,
    val auditStatus: String,
    val manifestDigest: String
) {
    /** The manifest's own integrity protection (mirror of the
     *  Windows ValidateIntegrity): a downgrade swap fails the
     *  digest; malformed pins, duplicate or escaping paths, and
     *  a binary path that is not one of the pinned files all
     *  fail here. Checked before any download or launch. */
    fun validateIntegrity(): Pair<Boolean, String> {
        if (artefacts.isEmpty())
            return false to "tor manifest integrity failure: no artefacts are pinned — refusing"
        val platforms = HashSet<String>()
        for (a in artefacts) {
            if (!platforms.add(a.platform))
                return false to "tor manifest integrity failure: duplicate artefact for platform '${a.platform}' — refusing"
            if (a.bundleSha256.length != 64 || !a.bundleSha256.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                return false to "tor manifest integrity failure: bundle pin for '${a.platform}' is not a SHA-256 hex digest — refusing"
            if (a.bundleSizeBytes <= 0)
                return false to "tor manifest integrity failure: bundle pin for '${a.platform}' carries a non-positive size — refusing"
            if (a.bundleFileName.contains('/') || a.bundleFileName.contains('\\') || a.bundleFileName.contains(".."))
                return false to "tor manifest integrity failure: bundle file name '${a.bundleFileName}' is not a plain file name — refusing"
            val seen = HashSet<String>()
            for (f in a.files) {
                if (f.bundlePath.contains("..") || f.bundlePath.startsWith("/") || f.bundlePath.contains('\\'))
                    return false to "tor manifest integrity failure: component file path '${f.bundlePath}' escapes the component home — refusing"
                if (!seen.add(f.bundlePath))
                    return false to "tor manifest integrity failure: duplicate component file path '${f.bundlePath}' — refusing"
                if (f.sha256.length != 64 || !f.sha256.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                    return false to "tor manifest integrity failure: pin for '${f.bundlePath}' is not a SHA-256 hex digest — refusing"
                if (f.sizeBytes <= 0)
                    return false to "tor manifest integrity failure: pin for '${f.bundlePath}' carries a non-positive size — refusing"
            }
            if (a.binaryBundlePath !in seen)
                return false to "tor manifest integrity failure: the binary path '${a.binaryBundlePath}' is not one of the pinned files — refusing"
        }
        if (manifestDigest.isBlank())
            return false to "tor manifest integrity failure: no manifest digest is recorded — refusing"
        val actual = computeManifestDigest(bundleVersion, downloadBaseUrl, artefacts)
        if (!actual.equals(manifestDigest, ignoreCase = true))
            return false to "tor manifest integrity failure: the manifest digest does not match the pinned artefact list — the manifest has been altered since its pins were captured; refusing"
        return true to "tor manifest integrity verified"
    }

    fun forPlatform(platform: String): TorArtefact? = artefacts.firstOrNull { it.platform == platform }

    companion object {
        /** Canonical digest, byte-identical to the Windows form:
         *  SHA-256 (lowercase hex) of "acp-tor-component\n" +
         *  bundleVersion + "\n" + downloadBaseUrl + "\n" + per
         *  artefact "platform|bundleFileName|bundleSha256|size\n"
         *  + per file "bundlePath|sha256-lowercase|size\n", UTF-8. */
        fun computeManifestDigest(bundleVersion: String, downloadBaseUrl: String, artefacts: List<TorArtefact>): String {
            val sb = StringBuilder()
            sb.append("acp-tor-component\n").append(bundleVersion).append('\n').append(downloadBaseUrl).append('\n')
            for (a in artefacts) {
                sb.append(a.platform).append('|').append(a.bundleFileName).append('|')
                    .append(a.bundleSha256.lowercase()).append('|').append(a.bundleSizeBytes).append('\n')
                for (f in a.files)
                    sb.append(f.bundlePath).append('|').append(f.sha256.lowercase()).append('|').append(f.sizeBytes).append('\n')
            }
            return sha256Hex(sb.toString().toByteArray(Charsets.UTF_8))
        }

        /** The production component: the Tor Project's expert
         *  bundle, Tor Browser 16.0.1 / Tor 0.4.9.16, pins
         *  captured 2026-11-22 from the author's own published
         *  sums and verified downloads. Identical to Windows. */
        val PRODUCTION = TorComponentManifest(
            bundleVersion = TorPins.BUNDLE_VERSION,
            torVersion = TorPins.TOR_VERSION,
            downloadBaseUrl = TorPins.DOWNLOAD_BASE_URL,
            artefacts = listOf(
                TorArtefact(TorPins.WINDOWS_X64, "tor-expert-bundle-windows-x86_64-16.0.1.tar.gz",
                    "9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b", 23767908L,
                    "tor/tor.exe",
                    listOf(
                        TorComponentFile("tor/tor.exe", "da22856f95ee24f8ace4ad1ab04acbd818fd6c3042bc3cf8f1d7cc3fa3edcb2b", 10248704L),
                        TorComponentFile("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                        TorComponentFile("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L)
                    )),
                TorArtefact(TorPins.ANDROID_ARM64, "tor-expert-bundle-android-aarch64-16.0.1.tar.gz",
                    "0091927b9fd72992a88021d55416b23a8380dc39a70c4b73a2cca9ee6a3dbcec", 19741621L,
                    "tor/libTor.so",
                    listOf(
                        TorComponentFile("tor/libTor.so", "de31ff6af868c17ce9ddc6519eccecd22eed5e371265d340543ef5c3de7ee293", 6598488L),
                        TorComponentFile("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                        TorComponentFile("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L)
                    )),
                TorArtefact(TorPins.LINUX_X64, "tor-expert-bundle-linux-x86_64-16.0.1.tar.gz",
                    "7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725", 33731966L,
                    "tor/tor",
                    listOf(
                        TorComponentFile("tor/tor", "0769509fb10e5b916d91f824fdb7575ae142f5afe134b16e9ea174074a327ccf", 3618712L),
                        TorComponentFile("tor/libcrypto.so.3", "e2c0901c520c07cdaab4af3507bf20f6c80273571764b4dc9b3b0b4a75621052", 5493040L),
                        TorComponentFile("tor/libssl.so.3", "cb31eaf171a10f660137b6c3d1ff552c2e89fdedd20e8523a7bf30cc06727457", 1056448L),
                        TorComponentFile("tor/libevent-2.1.so.7", "d252ad9c63de5ac276bdcf73f466ecf6ce0b390f33c3d241b6a32ea4e2f59ef6", 346424L),
                        TorComponentFile("data/geoip", "5f0ebc505ad5a5b219f9c053ce6228c837669364349a1a70c236192dd99a1c3d", 9855249L),
                        TorComponentFile("data/geoip6", "d6bc775efb8f970afacbb702ea0c80dbf9e2add32232afcfe3f376a972503b56", 16075127L)
                    ))
            ),
            auditStatus = "unaudited",
            manifestDigest = "8994bf10989e77f28e215949e946c1556ff6d8b79c69d81a156abec909e0910b"
        )

        /** A same-format fixture manifest (tests only): the
         *  caller supplies an artefact whose pins it computed
         *  from the fixture bytes. Fixture mode is explicit and
         *  named — never confused with the production component. */
        fun forFixture(baseUrl: String, artefact: TorArtefact): TorComponentManifest =
            TorComponentManifest("fixture-bundle", "fixture-tor", baseUrl, listOf(artefact),
                "unaudited-fixture", computeManifestDigest("fixture-bundle", baseUrl, listOf(artefact)))
    }
}

private fun sha256HexOfFile(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    FileInputStream(file).use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            digest.update(buf, 0, n)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/** Provisions the pinned Tor component into ACP-managed storage.
 *  Fetcher seam: (url, destFile) — production passes an HTTPS
 *  fetch; tests pass a fixture fetch. Every refusal is total:
 *  nothing partially installs. Mirror of the Windows
 *  TorProvisioner. */
class TorProvisioner(val manifest: TorComponentManifest) {

    /** Download + verify + install the component for [artefact]
     *  into [componentHome]. The bundle is verified (size, then
     *  SHA-256) before anything is extracted; every extracted
     *  file is verified against its own pin before it lands;
     *  only pinned files are extracted, and tar entry names are
     *  never used as filesystem paths. */
    fun provision(
        componentHome: File, artefact: TorArtefact,
        fetcher: (String, File) -> Unit,
        sourceBaseOverride: String? = null, fixtureMode: Boolean = false
    ): Pair<Boolean, String> {
        val integrity = manifest.validateIntegrity()
        if (!integrity.first) return integrity
        val source = sourceBaseOverride ?: manifest.downloadBaseUrl
        if (!fixtureMode && source != TorPins.DOWNLOAD_BASE_URL)
            return false to "tor: wrong source — the Tor component downloads only from the Tor Project's own distribution directory (${TorPins.DOWNLOAD_BASE_URL}); '$source' refused, no override"
        if (fixtureMode && source == TorPins.DOWNLOAD_BASE_URL)
            return false to "tor: fixture mode against the production source is refused — fixtures stay local and named"
        componentHome.mkdirs()
        val bundleFile = File(componentHome, artefact.bundleFileName + ".partial")
        try {
            fetcher(source.trimEnd('/') + "/" + artefact.bundleFileName, bundleFile)
        } catch (e: Exception) {
            bundleFile.delete()
            return false to "tor: download of ${artefact.bundleFileName} failed (${e.javaClass.simpleName}) — nothing installed"
        }
        if (!bundleFile.exists())
            return false to "tor: download of ${artefact.bundleFileName} produced no file — nothing installed"
        if (bundleFile.length() != artefact.bundleSizeBytes) {
            val got = bundleFile.length(); bundleFile.delete()
            return false to "tor: size mismatch for ${artefact.bundleFileName}: pinned ${artefact.bundleSizeBytes}, downloaded $got — refused, partial deleted"
        }
        val bundleHash = sha256HexOfFile(bundleFile)
        if (!bundleHash.equals(artefact.bundleSha256, ignoreCase = true)) {
            bundleFile.delete()
            return false to "tor: HASH MISMATCH for ${artefact.bundleFileName}: pinned ${artefact.bundleSha256}, downloaded $bundleHash — refused and reported; there is no override"
        }
        // Bundle verified. Extract ONLY the pinned files, each to
        // a staging path, verifying size + hash before it lands.
        val staging = File(componentHome, ".staging-" + System.nanoTime().toString(36))
        staging.mkdirs()
        try {
            val wanted = artefact.files.associateBy { it.bundlePath }
            val extracted = HashSet<String>()
            GZIPInputStream(FileInputStream(bundleFile)).use { gz ->
                val tar = TarReader(gz)
                while (true) {
                    val entry = tar.nextEntry() ?: break
                    if (!entry.isRegularFile) continue
                    val name = entry.name.replace('\\', '/').trimStart('.', '/')
                    val pin = wanted[name] ?: continue // unpinned entries are never written anywhere
                    val stageFile = File(staging, pin.bundlePath)
                    stageFile.parentFile?.mkdirs()
                    FileOutputStream(stageFile).use { out -> tar.copyEntryDataTo(out) }
                    val check = verifyFile(stageFile, pin)
                    if (!check.first) {
                        staging.deleteRecursively(); bundleFile.delete()
                        return check
                    }
                    extracted.add(pin.bundlePath)
                }
            }
            val missing = wanted.keys - extracted
            if (missing.isNotEmpty()) {
                staging.deleteRecursively(); bundleFile.delete()
                return false to "tor: the verified bundle does not contain the pinned file(s) ${missing.joinToString(", ")} — refused, nothing installed"
            }
            for (pin in artefact.files) {
                val from = File(staging, pin.bundlePath)
                val to = File(componentHome, pin.bundlePath)
                to.parentFile?.mkdirs()
                from.copyTo(to, overwrite = true)
                if (pin.bundlePath == artefact.binaryBundlePath) to.setExecutable(true, false)
            }
        } finally {
            bundleFile.delete()
            staging.deleteRecursively()
        }
        File(componentHome, INSTALL_RECORD_FILE_NAME).writeText(
            "{\"platform\":\"${artefact.platform}\",\"bundleVersion\":\"${manifest.bundleVersion}\"," +
                "\"torVersion\":\"${manifest.torVersion}\",\"bundleSha256\":\"${artefact.bundleSha256}\"}")
        return true to "tor: component installed — Tor ${manifest.torVersion} (expert bundle ${manifest.bundleVersion}, ${artefact.platform}); bundle and ${artefact.files.size} file(s) verified against the pinned hashes"
    }

    /** Re-verify the installed binary against its pin. The setup
     *  act calls this immediately before every launch: a tampered
     *  binary fails here and is never executed. */
    fun verifyInstalledBinary(componentHome: File, artefact: TorArtefact): Pair<Boolean, String> {
        val integrity = manifest.validateIntegrity()
        if (!integrity.first) return integrity
        val pin = artefact.files.first { it.bundlePath == artefact.binaryBundlePath }
        val path = File(componentHome, artefact.binaryBundlePath)
        if (!path.exists())
            return false to "tor: the provisioned Tor binary is missing (${artefact.binaryBundlePath}) — run Tor setup to provision it"
        return verifyFile(path, pin)
    }

    /** Re-verify EVERY installed component file against its pin. */
    fun verifyInstalled(componentHome: File, artefact: TorArtefact): Pair<Boolean, String> {
        val integrity = manifest.validateIntegrity()
        if (!integrity.first) return integrity
        for (pin in artefact.files) {
            val path = File(componentHome, pin.bundlePath)
            if (!path.exists()) return false to "tor: installed component file ${pin.bundlePath} is missing — the component must not run"
            val check = verifyFile(path, pin)
            if (!check.first) return check
        }
        return true to "tor: installed component verified against the pinned hashes"
    }

    private fun verifyFile(file: File, pin: TorComponentFile): Pair<Boolean, String> {
        if (file.length() != pin.sizeBytes)
            return false to "tor: size mismatch for ${pin.bundlePath}: pinned ${pin.sizeBytes}, found ${file.length()} — refused"
        val actual = sha256HexOfFile(file)
        if (!actual.equals(pin.sha256, ignoreCase = true))
            return false to "tor: HASH MISMATCH for ${pin.bundlePath}: pinned ${pin.sha256}, found $actual — refused; the file must not be used"
        return true to "verified"
    }

    companion object {
        const val INSTALL_RECORD_FILE_NAME = "tor-install.json"
    }
}

/** Minimal read-only tar reader (ustar): enough to walk a
 *  gzip'd expert bundle. Entry data is streamed; the reader
 *  never interprets an entry name as a filesystem path — the
 *  provisioner matches names against its pin list and writes
 *  only to paths built from the pins. */
private class TarReader(private val input: java.io.InputStream) {
    class Entry(val name: String, val size: Long, val isRegularFile: Boolean)

    private var current: Entry? = null
    private var remainingInEntry: Long = 0
    private var padding: Long = 0

    fun nextEntry(): Entry? {
        skipFully(remainingInEntry + padding)
        val header = ByteArray(512)
        if (!readFully(header)) return null
        if (header.all { it == 0.toByte() }) return null
        val nameField = String(header, 0, 100, Charsets.UTF_8).trimEnd('\u0000', ' ')
        val prefix = if (String(header, 257, 6, Charsets.UTF_8).startsWith("ustar"))
            String(header, 345, 155, Charsets.UTF_8).trimEnd('\u0000', ' ') else ""
        val name = if (prefix.isNotEmpty()) "$prefix/$nameField" else nameField
        val sizeText = String(header, 124, 12, Charsets.UTF_8).trim('\u0000', ' ')
        val size = if (sizeText.isEmpty()) 0L else sizeText.toLong(8)
        val type = header[156].toInt().toChar()
        current = Entry(name, size, type == '0' || type == '\u0000')
        remainingInEntry = size
        padding = (512 - (size % 512)) % 512
        return current
    }

    fun copyEntryDataTo(out: java.io.OutputStream) {
        var left = remainingInEntry
        val buf = ByteArray(64 * 1024)
        while (left > 0) {
            val n = input.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (n < 0) break
            out.write(buf, 0, n)
            left -= n
        }
        remainingInEntry = 0
    }

    private fun skipFully(count: Long) {
        var left = count
        val buf = ByteArray(64 * 1024)
        while (left > 0) {
            val n = input.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (n < 0) break
            left -= n
        }
    }

    private fun readFully(buf: ByteArray): Boolean {
        var read = 0
        while (read < buf.size) {
            val n = input.read(buf, read, buf.size - read)
            if (n < 0) return read > 0 && false
            read += n
        }
        return true
    }
}

/** The process seam for the ACP-managed Tor client. The app
 *  supplies the real process runner; tests supply a fake that
 *  records launches (the destruction proof that a tampered
 *  binary is never executed asserts on this seam). */
interface TorProcessRunner {
    val isRunning: Boolean
    fun start(binaryPath: File, torrcPath: File, workingDir: File)
    fun stop()
}

/** The Tor setup act (A2 spec, mirror of the Windows
 *  TorSetupService): provision if needed, re-verify the
 *  installed binary, launch the ACP-managed Tor client as a
 *  local-only SOCKS listener, and — only once the SOCKS port
 *  answers — write the tor.json the `tor` rung's configuration
 *  is read from. This act is the ONLY writer of tor.json. Every
 *  failure is a named refusal and leaves no tor.json behind. */
class TorSetupService(
    private val provisioner: TorProvisioner,
    private val process: TorProcessRunner,
    private val componentHome: File,
    private val dataDir: File
) {
    val manifest: TorComponentManifest get() = provisioner.manifest
    val torConfigPath: File get() = File(dataDir, "tor.json")

    fun runSetup(
        fetcher: (String, File) -> Unit,
        fixtureMode: Boolean = false,
        sourceBaseOverride: String? = null,
        platform: String = TorPins.ANDROID_ARM64,
        socksPort: Int = TorPins.SOCKS_PORT,
        socksWaitMs: Long = 60_000
    ): Pair<Boolean, String> {
        // W20 (W19-C parity): the setup act is policy-gated under
        // rmm.tor_provisioning.enabled, as on Windows — a policy
        // disabling the toggle refuses the act BY NAME before any
        // provisioning or launch. stopAndUnconfigure is never
        // gated (a stop is never policy-gated). With no policy
        // bound, PolicyGate falls back to the registry default ON.
        if (!PolicyGate.enabledFor(TOR_PROVISIONING_TOGGLE, true))
            return false to "tor: Tor component provisioning is disabled by policy ($TOR_PROVISIONING_TOGGLE) — the setup act is refused; status stays readable and stop/unconfigure stays available"
        val artefact = provisioner.manifest.forPlatform(platform)
            ?: return false to "tor: no pinned Tor artefact for this platform — Tor setup cannot provision this device"
        val binaryPath = File(componentHome, artefact.binaryBundlePath)
        if (!binaryPath.exists()) {
            val provisioned = provisioner.provision(componentHome, artefact, fetcher, sourceBaseOverride, fixtureMode)
            if (!provisioned.first) return provisioned
        }
        // Re-verify immediately before launch — every launch, no
        // exceptions. A tampered binary fails here and never runs.
        val verified = provisioner.verifyInstalledBinary(componentHome, artefact)
        if (!verified.first) return false to (verified.second + " — the Tor client was NOT started")
        File(componentHome, "data").mkdirs()
        val torrcPath = File(componentHome, "torrc")
        torrcPath.writeText(buildTorrc(componentHome, socksPort))
        if (!process.isRunning) {
            try {
                process.start(binaryPath, torrcPath, componentHome)
            } catch (e: Exception) {
                return false to "tor: the verified Tor client failed to start (${e.javaClass.simpleName}) — no Tor configuration written"
            }
        }
        if (!waitForSocks(TorPins.SOCKS_HOST, socksPort, socksWaitMs)) {
            try { process.stop() } catch (_: Exception) {}
            torConfigPath.delete()
            return false to "tor: the Tor client did not open its local SOCKS listener on ${TorPins.SOCKS_HOST}:$socksPort — no Tor configuration written; the rung stays unconfigured"
        }
        dataDir.mkdirs()
        torConfigPath.writeText("{\"socksHost\":\"${TorPins.SOCKS_HOST}\",\"socksPort\":$socksPort}")
        return true to "tor: ACP-managed Tor client running — local SOCKS proxy at ${TorPins.SOCKS_HOST}:$socksPort, binary verified against its pin before launch; tor.json written by Tor setup"
    }

    /** Stop the ACP-managed client and remove the rung's
     *  configuration, so the rung returns to its honest
     *  unconfigured refusal. */
    fun stopAndUnconfigure() {
        try { process.stop() } catch (_: Exception) {}
        torConfigPath.delete()
    }

    private fun waitForSocks(host: String, port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), 2000)
                    val out = socket.getOutputStream()
                    val input = socket.getInputStream()
                    out.write(byteArrayOf(5, 1, 0)); out.flush()
                    val reply = ByteArray(2)
                    var read = 0
                    while (read < 2) {
                        val n = input.read(reply, read, 2 - read)
                        if (n < 0) break
                        read += n
                    }
                    if (read == 2 && reply[0].toInt() == 5 && reply[1].toInt() == 0) return true
                }
            } catch (_: Exception) { /* not up yet */ }
            Thread.sleep(250)
        }
        return false
    }

    companion object {
        /** The RMM-07 registry key governing the setup act
         *  (W19-C on Windows, mirrored W20): registered in
         *  FeatureToggleRegistry.seeded under directive A2. */
        const val TOR_PROVISIONING_TOGGLE = "rmm.tor_provisioning.enabled"

        /** The generated torrc: exactly one listener, a SOCKS
         *  port on loopback. No control port, no OR port —
         *  local-only by construction. */
        fun buildTorrc(componentHome: File, socksPort: Int): String {
            val home = componentHome.absolutePath.replace('\\', '/')
            return buildString {
                appendLine("# ACP-managed Tor client (A2). Generated by ACP Tor setup — do not edit;")
                appendLine("# the setup act regenerates it on every run.")
                appendLine("# Pinned component: Tor ${TorPins.TOR_VERSION}, Tor Browser expert bundle ${TorPins.BUNDLE_VERSION}.")
                appendLine("SocksPort ${TorPins.SOCKS_HOST}:$socksPort")
                appendLine("DataDirectory $home/data")
                appendLine("GeoIPFile $home/data/geoip")
                appendLine("GeoIPv6File $home/data/geoip6")
                appendLine("ClientOnly 1")
            }
        }

        /** Read the configuration the setup act wrote (the
         *  Android rung's TorConfig source). Absent/malformed =
         *  unconfigured, and the rung refuses honestly. */
        fun readTorConfig(dataDir: File): TorConfig? {
            val file = File(dataDir, "tor.json")
            if (!file.exists()) return null
            val text = try { file.readText() } catch (_: Exception) { return null }
            val host = Regex("\"socksHost\"\\s*:\\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1) ?: return null
            val port = Regex("\"socksPort\"\\s*:\\s*(\\d+)").find(text)?.groupValues?.get(1)?.toIntOrNull() ?: return null
            return if (port > 0) TorConfig(host, port) else null
        }
    }
}
