package io.agenticcontrol.app.deploy

import io.agenticcontrol.app.cameraview.ChainedAudit
import java.security.MessageDigest

/**
 * RMM-16 (Android completion) — general deployment, app-tier bound.
 * The bound is STATED IN THE SURFACE ([SURFACE_BOUND]): at the app
 * tier every install is installer-mediated and user-confirmed;
 * silent install of arbitrary packages is a Device Owner capability
 * this app does not hold and never claims. Content packs and profile
 * content ride the existing verified-update machinery's shape:
 * signed manifest, hash-verified payloads, fail-closed.
 * RMM-14 decision (2026-11-21): the phone is a pure CONSUMER of
 * distribution, never a peer/cache — no distribution code here.
 */
object DeployPolicy {
    // bd-and-rmm F2: the registry key is rmm.software_deployment.enabled
    // (the old rmm.deployment.enabled existed nowhere in the registry).
    // bd-and-rest F5 fix: local default OFF like BackupPolicy — the
    // owner turns deployment on; a bound ManagementPolicyEngine
    // still governs through PolicyGate either way.
    @Volatile var enabled: Boolean = false // rmm.software_deployment.enabled, local default OFF
    @Volatile var contentPacksEnabled: Boolean = true
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.software_deployment.enabled", enabled)
}
const val SURFACE_BOUND = "Installs on this device are confirmed by the person holding it in the system installer. This app cannot install packages silently; silent deployment requires a managed (Device Owner) device."

fun interface SignatureVerifier { fun verifyManifest(manifestBytes: ByteArray, signature: String): Boolean }
fun interface InstallerHandoff { fun handToInstaller(packageId: String, payloadHash: String): Boolean }

/** bd-and-rest F9 fix: a payload-carrying handoff — the installer
 *  receives the VERIFIED payload bytes themselves (the platform
 *  layer turns them into the FileProvider URI the system installer
 *  reads), not just an id and a hash it cannot act on. When wired
 *  it replaces the legacy id+hash handoff for APK units. */
fun interface PayloadInstallerHandoff { fun handToInstaller(packageId: String, payloadHash: String, payload: ByteArray): Boolean }

data class DeployUnit(
    val id: String, val kind: String, // apk | content_pack | profile
    val version: String, val payloadHash: String, val licenceNote: String = ""
)
data class ContentPack(val id: String, val title: String, val entries: List<String>, val hash: String)

class DeployService(
    private val verifier: SignatureVerifier,
    private val installer: InstallerHandoff,
    val audit: ChainedAudit = ChainedAudit(),
    /** bd-and-rest F9 fixes: the payload-carrying installer
     *  handoff, and a persistence sink for content packs (the
     *  platform layer writes them through to disk; without a sink
     *  packs stay in-memory, as before, and no surface claims
     *  otherwise). */
    private val payloadInstaller: PayloadInstallerHandoff? = null,
    private val packSink: ((ContentPack) -> Unit)? = null
) {
    private val packs = mutableMapOf<String, ContentPack>()

    /** Restore a persisted content pack (platform layer, at
     *  composition). Not an install: no audit line, no policy. */
    @Synchronized
    fun restorePack(pack: ContentPack) { packs[pack.id] = pack }
    fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Synchronized
    fun deploy(unit: DeployUnit, manifestBytes: ByteArray, signature: String, payload: ByteArray, userConfirmed: Boolean): Result<String> {
        fun refuse(r: String): Result<String> { audit.append("deploy_refused", "unit=${unit.id} reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!DeployPolicy.isEnabled()) return refuse("policy rmm.software_deployment.enabled is OFF")
        if (unit.kind !in setOf("apk", "content_pack", "profile")) return refuse("unknown content type: ${unit.kind}")
        if (!verifier.verifyManifest(manifestBytes, signature)) return refuse("manifest signature verification failed")
        if (sha(payload) != unit.payloadHash) return refuse("payload hash mismatch")
        return when (unit.kind) {
            "apk" -> {
                if (!userConfirmed) refuse("installer-mediated: user confirmation is required at the app tier")
                else if (payloadInstaller != null && !payloadInstaller.handToInstaller(unit.id, unit.payloadHash, payload)) refuse("system installer handoff failed")
                else if (payloadInstaller == null && !installer.handToInstaller(unit.id, unit.payloadHash)) refuse("system installer handoff failed")
                else { audit.append("deploy_apk_handed_to_installer", "unit=${unit.id} version=${unit.version}"); Result.success("handed to system installer for user confirmation") }
            }
            "content_pack" -> {
                if (!DeployPolicy.contentPacksEnabled) refuse("content packs disabled by policy")
                else {
                    val pack = ContentPack(unit.id, unit.id, String(payload, Charsets.UTF_8).lines().filter { it.isNotBlank() }, unit.payloadHash)
                    packs[unit.id] = pack
                    try { packSink?.invoke(pack) } catch (_: Exception) { /* persistence is best-effort beside the in-memory pack */ }
                    audit.append("deploy_content_pack", "unit=${unit.id} entries=${pack.entries.size}")
                    Result.success("content pack installed: ${pack.entries.size} entries")
                }
            }
            // bd-and-rest F9 fix: 'profile' used to audit
            // "profile content applied" and return success while
            // applying NOTHING. There is no profile applier at the
            // app tier, so the honest answer is a refusal.
            else -> refuse("profile content application is not implemented at the app tier (no applier exists) — refused rather than claimed")
        }
    }
    @Synchronized fun pack(id: String): ContentPack? = packs[id]
    @Synchronized fun packs(): List<ContentPack> = packs.values.toList()
}
