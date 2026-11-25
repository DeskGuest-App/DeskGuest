package io.agenticcontrol.app.rmmspine

import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.enterprise.PolicyBundle
import org.json.JSONObject
import java.io.File

/**
 * RMM-07 completion — Android mirror. Mirrors Windows
 * Acp.Shared/ManagementPolicy/ManagementPolicy.cs: the rmm.*
 * TOTAL POLICY CONTROL registry on-device (extending the signed
 * receipt path beyond the 8-key Block E PolicyFeatures set),
 * org → group → device inheritance with override and
 * revert-to-inherited, dynamic attribute targeting, and the
 * Effective Policy resolution the on-device view renders.
 * THE CONSENT FLOOR IS NEVER A SETTING: ConsentFloorGuard refuses
 * floor-naming keys at document AND registry admission, any dotted
 * segment, any case — a document carrying one refuses WHOLE.
 */
object PolicyLevels {
    const val ORG = "org"; const val GROUP = "group"; const val DEVICE = "device"
    val ALL = setOf(ORG, GROUP, DEVICE)
}

object ConsentFloorGuard {
    private val deniedExact = setOf("presence", "stop", "audit", "consent", "consent_floor", "consent.floor",
        "presence.enabled", "presence.visible", "presence.hide", "presence_indicator",
        "stop.enabled", "stop.disabled", "stop_button", "kill_switch",
        "audit.enabled", "audit.editable", "audit.deletable", "audit_chain")
    private val deniedPrefixes = listOf("presence.", "stop.", "audit.", "consent.", "consent_floor.")
    private val deniedSegments = setOf("presence", "stop", "audit", "consent", "consent_floor")

    fun isDenied(key: String?): Boolean {
        // W12-DS P7-F3: port the Windows normalisation — strip
        // format characters (zero-width etc.), split on EVERY
        // separator (., -, /, _, space, tab), and compare each
        // segment with separators removed, so compound names
        // (audit_chain, kill_switch, kill-switch, rmm_stop) are
        // denied exactly as on Windows.
        val k = (key ?: "").filter { it.category != CharCategory.FORMAT }.trim().lowercase()
        if (k.isEmpty()) return false
        if (k in deniedExact) return true
        if (deniedPrefixes.any { k.startsWith(it) }) return true
        val segments = k.split(Regex("[.\\-/ _\t]+")).map { it.replace("_", "").replace("-", "") }
        if (segments.any { it in setOf("presence", "stop", "audit", "consent", "consentfloor") }) return true
        // Compound names span segments (kill_switch, kill-switch,
        // audit_chain): check the separator-stripped whole key.
        val whole = segments.joinToString("")
        return listOf("killswitch", "auditchain", "stopbutton", "consentfloor").any { whole.contains(it) }
    }

    fun checkDocument(doc: ManagementPolicyDocument): String? {
        for (key in doc.settings.keys) if (isDenied(key))
            return "policy document '${doc.id}' carries consent-floor key '$key' — REFUSED: the consent floor is never a setting (presence, STOP and the audit chain have no toggle)"
        return null
    }
}

data class FeatureToggle(val key: String, val directive: String, val defaultEnabled: Boolean, val description: String)

/** The registry, seeded with the Windows RMM-07 catalogue verbatim
 *  (keys + defaults). Registering a consent-floor key throws. */
class FeatureToggleRegistry {
    private val toggles = mutableMapOf<String, FeatureToggle>()
    fun register(t: FeatureToggle) {
        val key = t.key.trim().lowercase()
        require(key.isNotEmpty()) { "feature toggle key is empty" }
        if (ConsentFloorGuard.isDenied(key))
            throw IllegalStateException("feature key '$key' names the consent floor — the registry REFUSES to carry it")
        synchronized(this) { toggles[key] = t.copy(key = key) }
    }
    fun get(key: String?): FeatureToggle? = synchronized(this) { toggles[(key ?: "").trim().lowercase()] }
    fun all(): List<FeatureToggle> = synchronized(this) { toggles.values.sortedBy { it.key } }

    companion object {
        fun seeded(): FeatureToggleRegistry {
            val r = FeatureToggleRegistry()
            fun add(d: String, k: String, def: Boolean, desc: String) = r.register(FeatureToggle(k, d, def, desc))
            add("RMM-01", "rmm.monitoring.enabled", true, "Continuous endpoint health monitoring + threshold alerting")
            add("RMM-02", "rmm.patch.enabled", true, "Patch management (OS + third-party, approvals, rings)")
            add("RMM-03", "rmm.signed_commands.enabled", true, "Endpoint Takeover Prevention: signed commands, endpoint-verified")
            add("RMM-04", "rmm.inventory.enabled", true, "Continuous fleet inventory")
            add("RMM-04", "rmm.inventory.warrantyLookup.enabled", true, "Warranty lookup by serial (hub-side, OEM hosts only)")
            add("RMM-04", "rmm.inventory.unmanagedRegister.enabled", true, "Unmanaged-asset register")
            add("RMM-05", "rmm.vulnerability.enabled", true, "Vulnerability management loop")
            add("RMM-06", "rmm.backup.enabled", true, "Endpoint backup to user-owned storage")
            add("RMM-07", "rmm.policy.enabled", true, "Management-policy inheritance + Effective Policy")
            add("RMM-08", "rmm.remediation.enabled", true, "Auto-remediation engine")
            add("RMM-09", "rmm.compliance.enabled", true, "Compliance evidence packs")
            add("RMM-10", "rmm.backstage.enabled", false, "Background tools / Backstage — default OFF (presence tension recorded)")
            add("RMM-10", "rmm.background_tools.enabled", false, "Background toolset — default OFF, separate scope required")
            add("RMM-11", "rmm.network_discovery.enabled", true, "Network discovery + agentless monitoring")
            add("RMM-11", "rmm.probes.enabled", true, "On-phone probe suite (SNMP / topology / agentless checks) — bd-and-rmm F2: the key Probes.kt always named, registered 2026-11-22")
            add("RMM-11-EXT", "rmm.camera_viewing.enabled", false, "Camera viewing (ONVIF/RTSP only)")
            add("RMM-12", "rmm.work_items.enabled", true, "Work items (ticket-lite)")
            add("RMM-13", "rmm.reporting.enabled", true, "Local reporting + hub API/webhooks")
            add("RMM-14", "rmm.p2p_distribution.enabled", true, "P2P LAN distribution + patch caching")
            add("RMM-15", "rmm.job_resume.enabled", true, "Job resume-on-reconnect")
            add("RMM-16", "rmm.software_deployment.enabled", true, "Software deployment: package repository + content packs")
            add("RMM-17", "rmm.endpoint_security.enabled", true, "Endpoint security posture")
            add("RMM-18", "rmm.encryption_enforcement.enabled", true, "Disk-encryption enforcement + recovery-key escrow")
            add("RMM-19", "rmm.baselines.enabled", true, "Desired-state baselines + drift detection")
            add("RMM-20", "rmm.runbooks.enabled", true, "Runbooks: approval-gated SOP execution chains")
            add("RMM-21", "rmm.site_documentation.enabled", true, "Site documentation + credential vault, surfaced in-session")
            add("RMM-21", "rmm.vault_surfacing.enabled", true, "Credential vault surfacing in-session (metadata + gated reveal) — bd-and-rmm F2: the key InSession.kt always named, registered 2026-11-22")
            add("RMM-22", "rmm.camera_share.enabled", true, "Camera-share sessions")
            add("RMM-23", "rmm.vendor_passes.enabled", true, "Privileged access passes for vendors")
            add("RMM-23", "rmm.browser_hardening.enabled", true, "Browser hardening policy (W12-DS P7-F6: its own toggle, as on Windows — a vendor-pass kill switch must not blind it)")
            add("RMM-24", "rmm.enrollment_push.enabled", true, "Directory-driven enrollment push")
            add("RMM-24", "rmm.mobile_operator.enabled", true, "Mobile operator client (W12-DS P7-F6: its own toggle, as on Windows)")
            add("RMM-25", "rmm.app_control.enabled", true, "Application control (allow/blocklisting)")
            add("RMM-26", "rmm.metering.enabled", true, "Software metering + licence-compliance reporting")
            add("RMM-27", "rmm.anomaly_baselining.enabled", true, "Local anomaly baselining for alert quality")
            add("RMM-28", "rmm.health_scoring.enabled", true, "Endpoint health scoring (DEX-style)")
            add("RMM-29", "rmm.imaging.enabled", true, "OS imaging / provisioning + profile migration")
            add("RMM-30", "rmm.usb_control.enabled", true, "USB/peripheral control + removable-media tracing")
            add("RMM-31", "rmm.mdm.enabled", false, "MDM subset for site devices — default OFF (APNs/FCM push transit is a named platform caveat)")
            add("RMM-32", "rmm.dlp.enabled", false, "Endpoint DLP + sensitive-data discovery — default OFF")
            add("U4", "rmm.session_budget.enabled", true, "Per-session agent budgets + tripwires (U4): per-class caps counted per session at the MCP choke point; a breach PAUSES the session. Caps are plain settings keys session_budget.cap.<class>")
            add("U1", "rmm.clipboard_policy.enabled", true, "Clipboard direction policy (U1): clipboard transfer direction is policy-controlled — plain settings keys clipboard.direction (both|host_to_agent|agent_to_host|off) and clipboard.sensitive_skip (default on: a sensitive-class clip is refused by name, never returned), resolved by ClipboardPolicy.fromSettings and enforced in AccessToolHost at the clipboard itself")
            // W20 mirror of the Windows W19-C registrations
            // (ManagementPolicy.cs A2/A3): key, directive and
            // default verbatim. Tor provisioning is a real Android
            // act (transport/TorProvisioning.kt, A2 — the
            // android-aarch64 artefact is pinned there and
            // TorSetupService.runSetup is gated on this toggle);
            // the AiPack download act is a Windows-host act, so
            // its description names the Android posture, the way
            // the warrantyLookup entry names its hub-side posture.
            add("A2", "rmm.tor_provisioning.enabled", true, "Tor component provisioning (A2, W19-C wiring): the owner-initiated Tor setup act — downloads ONLY the pinned Tor expert bundle from the Tor Project's own distribution directory, verifies bundle + per-file hashes against the pins before any launch, and writes tor.json only once the local SOCKS listener answers. Disabling this toggle refuses the setup act by name; status stays readable and stop/unconfigure stays available (a stop is never policy-gated)")
            add("A3", "rmm.aipack_download.enabled", true, "Local AI pack download (D25/A3, W19-C wiring): the owner-initiated download of the UI-TARS-1.5-7B pack from the author's official source ONLY, licence acceptance required first, every file verified against the hashes pinned in the product before it lands in the pack home; refuses on any mismatch with no override. Disabling this toggle refuses the download act by name; status/verify stay readable and cancel stays available — Android posture (W20 mirror): catalogue key only on this platform; the pack download act is a Windows-host act and no Android act downloads the pack, so the key resolves policy identically here but gates no on-device act")
            return r
        }
    }
}

data class ManagementPolicyDocument(
    val id: String, val level: String, val targetId: String,
    val settings: Map<String, String>, val revision: Long
) {
    /** Deterministic canonical JSON (keys sorted ordinal) — the
     *  exact bytes an RMM-03 policy_delivery envelope carries. */
    fun toCanonicalJson(): String {
        val s = JSONObject()
        for ((k, v) in settings.toSortedMap()) s.put(k, v)
        return JSONObject().put("id", id).put("level", level).put("targetId", targetId)
            .put("revision", revision).put("settings", s).toString()
    }

    companion object {
        const val INHERIT_MARKER = "__inherit__"
        fun fromCanonicalJson(json: String): ManagementPolicyDocument? = try {
            val root = JSONObject(json)
            val so = root.getJSONObject("settings")
            val settings = mutableMapOf<String, String>()
            val keys = so.keys()
            while (keys.hasNext()) { val k = keys.next(); settings[k] = so.getString(k) }
            ManagementPolicyDocument(root.getString("id"), root.getString("level"),
                root.getString("targetId"), settings, root.getLong("revision"))
        } catch (_: Exception) { null }
    }
}

interface DeviceFacts {
    val deviceId: String; val scopeId: String
    val directGroupIds: Set<String>; val attributes: Map<String, String>; val installedSoftware: Set<String>
}
data class StaticDeviceFacts(
    override val deviceId: String, override val scopeId: String,
    override val directGroupIds: Set<String> = emptySet(),
    override val attributes: Map<String, String> = emptyMap(),
    override val installedSoftware: Set<String> = emptySet()
) : DeviceFacts

data class GroupRule(val kind: String, val attribute: String?, val value: String?) {
    fun matches(f: DeviceFacts): Boolean = when (kind.trim().lowercase()) {
        "attribute_equals" -> attribute != null && f.attributes.entries.any {
            it.key.equals(attribute, true) && it.value.equals(value ?: "", true) }
        // W12-DS P7-F4: a null/blank contains-value matches
        // EVERYTHING in Kotlin (contains("") == true) — Windows
        // refuses it; here it matches NOTHING.
        "attribute_contains" -> !value.isNullOrBlank() && attribute != null && f.attributes.entries.any {
            it.key.equals(attribute, true) && it.value.contains(value, true) }
        "software_installed" -> value != null && f.installedSoftware.any { it.equals(value, true) }
        "tag" -> (f.attributes.entries.firstOrNull { it.key.equals("tags", true) }?.value ?: "")
            .split(',').map { it.trim() }.any { it.equals(value ?: "", true) }
        else -> false // unknown rule kind matches NOTHING (fail closed)
    }
}
data class GroupDefinition(val id: String, val name: String, val rules: List<GroupRule>) {
    fun isMember(f: DeviceFacts): Boolean =
        f.directGroupIds.any { it.equals(id, true) } || rules.any { it.matches(f) }
}

data class EffectiveSetting(val key: String, val value: String, val sourceLevel: String,
    val sourceTargetId: String, val sourceDocumentId: String)
data class EffectivePolicy(val deviceId: String, val scopeId: String,
    val settings: Map<String, EffectiveSetting>, val memberGroupIds: List<String>) {
    fun get(key: String?): EffectiveSetting? = settings[(key ?: "").trim().lowercase()]
}
data class PolicyVerdict(val allowed: Boolean, val reason: String)

class ManagementPolicyEngine(val registry: FeatureToggleRegistry = FeatureToggleRegistry.seeded()) {
    private val docs = mutableMapOf<String, ManagementPolicyDocument>()
    private val groups = mutableMapOf<String, GroupDefinition>()

    // W13 P7-F17: callers get DEFENSIVE COPIES — the stored
    // documents' settings maps were previously shared, so a caller
    // mutating a returned document silently rewrote live policy.
    fun documents(): List<ManagementPolicyDocument> = synchronized(this) {
        docs.values.sortedBy { it.id }.map { it.copy(settings = LinkedHashMap(it.settings)) }
    }
    // W12-DS P7-F5: validate + freeze — blank id refused, a
    // non-identical redefinition refused (no silent widening of a
    // group a signed document already targets), rules copied.
    fun addGroup(g: GroupDefinition): Boolean {
        if (g.id.isBlank()) return false
        synchronized(this) {
            val existing = groups[g.id.lowercase()]
            if (existing != null && (existing.name != g.name || existing.rules != g.rules)) return false
            groups[g.id.lowercase()] = g.copy(rules = g.rules.toList())
            return true
        }
    }
    fun groupList(): List<GroupDefinition> = synchronized(this) { groups.values.sortedBy { it.id } }

    /** Admission: consent-floor / level / revision discipline.
     *  The admitted document is a DEFENSIVE COPY, frozen at
     *  admission (the Windows RMM-07 destruction break, applied). */
    fun addDocument(doc: ManagementPolicyDocument?): PolicyVerdict {
        if (doc == null) return PolicyVerdict(false, "no policy document — refused")
        if (doc.id.isBlank() || doc.targetId.isBlank()) return PolicyVerdict(false, "policy document needs an id and a target — refused")
        if (doc.level !in PolicyLevels.ALL) return PolicyVerdict(false, "unknown policy level '${doc.level}' — refused")
        ConsentFloorGuard.checkDocument(doc)?.let { return PolicyVerdict(false, it) }
        if (doc.settings.keys.any { it.isBlank() }) return PolicyVerdict(false, "policy document '${doc.id}' carries an empty setting key — refused")
        synchronized(this) {
            docs[doc.id]?.let { existing ->
                if (doc.revision < existing.revision)
                    return PolicyVerdict(false, "policy document '${doc.id}' revision ${doc.revision} is stale (current ${existing.revision}) — refused")
                if (doc.revision == existing.revision && doc.toCanonicalJson() != existing.toCanonicalJson())
                    return PolicyVerdict(false, "policy document '${doc.id}' revision ${doc.revision} conflicts with the admitted document of the same id+revision — refused")
                if (doc.revision == existing.revision)
                    return PolicyVerdict(true, "policy document '${doc.id}' r${doc.revision} already admitted (idempotent)")
            }
            docs[doc.id] = doc.copy(settings = LinkedHashMap(doc.settings))
            return PolicyVerdict(true, "policy document '${doc.id}' r${doc.revision} admitted at ${doc.level} level for '${doc.targetId}'")
        }
    }

    fun memberGroupIds(f: DeviceFacts): List<String> = synchronized(this) {
        groups.values.filter { it.isMember(f) }.map { it.id }.sorted()
    }

    /** Org (scope or *) → groups in ORDINAL group-id order
     *  (insertion order cannot flip an outcome) → device. The
     *  inherit marker leaves the inherited value + provenance. */
    fun computeEffective(f: DeviceFacts): EffectivePolicy {
        val member = memberGroupIds(f)
        val memberSet = member.map { it.lowercase() }.toSet()
        val all = documents()
        val acc = mutableMapOf<String, EffectiveSetting>()
        // W12-DS P7-F9: org locks — an org document's
        // "policy.lock.<key>" makes group/device settings for that
        // key inert (Windows bd-sec-2/F4 parity).
        val locks = mutableSetOf<String>()
        for (doc in all.filter { it.level == PolicyLevels.ORG && (it.targetId == f.scopeId || it.targetId == "*") })
            for ((rawKey, value) in doc.settings) {
                val key = rawKey.trim().lowercase()
                if (key.startsWith("policy.lock.") && value.equals("true", true))
                    locks.add(key.removePrefix("policy.lock."))
            }
        fun apply(levelDocs: List<ManagementPolicyDocument>, honourLocks: Boolean) {
            // W12-DS P7-F10: revision is a sort key — a higher
            // revision wins over a later-sorting stale id.
            for (doc in levelDocs.sortedWith(compareBy({ it.targetId }, { it.revision }, { it.id })))
                for ((rawKey, value) in doc.settings) {
                    val key = rawKey.trim().lowercase()
                    if (key.startsWith("policy.lock.")) continue
                    if (honourLocks && key in locks) continue
                    if (value == ManagementPolicyDocument.INHERIT_MARKER) continue
                    acc[key] = EffectiveSetting(key, value, doc.level, doc.targetId, doc.id)
                }
        }
        apply(all.filter { it.level == PolicyLevels.ORG && (it.targetId == f.scopeId || it.targetId == "*") }, honourLocks = false)
        apply(all.filter { it.level == PolicyLevels.GROUP && it.targetId.lowercase() in memberSet }, honourLocks = true)
        apply(all.filter { it.level == PolicyLevels.DEVICE && it.targetId == f.deviceId }, honourLocks = true)
        return EffectivePolicy(f.deviceId, f.scopeId, acc, member)
    }

    /** THE TOTAL POLICY CONTROL query: floor → false; unknown →
     *  false; explicit value wins; unparsable explicit → false;
     *  otherwise the registry default. */
    fun isEnabled(f: DeviceFacts, featureKey: String?): Boolean {
        val key = (featureKey ?: "").trim().lowercase()
        if (ConsentFloorGuard.isDenied(key)) return false
        val eff = computeEffective(f).get(key)
        if (eff != null) return eff.value.toBooleanStrictOrNull() ?: false
        return registry.get(key)?.defaultEnabled ?: false
    }
}

/**
 * bd-and-rmm F2 fix (2026-11-22): the bridge from the signed
 * policy engine to the module policy objects. The per-module
 * @Volatile policy vars (BgToolsPolicy, ProbesPolicy, …) were
 * process-global switches the engine never read, so a signed
 * policy could not reach them. Now: when a ManagementPolicyReceipt
 * applies (or refuses) a document it BINDS the engine + this
 * device's facts here, and each module policy query goes through
 * [enabledFor]: engine verdict when bound, the module's local
 * var when not (the JVM suites and the pre-policy device posture).
 * Keys are REGISTRY keys — a module naming a key the registry does
 * not carry fails closed (false), never silently on.
 */
object PolicyGate {
    @Volatile
    var engine: ManagementPolicyEngine? = null
        private set
    @Volatile
    var facts: DeviceFacts? = null
        private set

    fun bind(engine: ManagementPolicyEngine, facts: DeviceFacts) {
        this.engine = engine
        this.facts = facts
    }

    fun unbind() {
        engine = null
        facts = null
    }

    /** The governing state of [registryKey]: the bound engine's
     *  isEnabled (registry default / explicit document value) when
     *  an engine is bound; [localFallback] otherwise. */
    fun enabledFor(registryKey: String, localFallback: Boolean): Boolean {
        val e = engine ?: return localFallback
        val f = facts ?: return localFallback
        return e.isEnabled(f, registryKey)
    }
}

/** Bridge: the Block E signed PolicyBundle projected into the
 *  engine as an org document (Windows EnterpriseBundleBridge). */
object EnterpriseBundleBridge {
    fun fromBundle(b: PolicyBundle): ManagementPolicyDocument {
        val s = mutableMapOf<String, String>()
        s["transport.ceiling"] = b.transportCeiling.joinToString(",")
        s["transport.mode"] = b.transportMode
        s["enterprise.forbid_ai_pairings"] = b.forbidAiPairings.toString()
        s["enterprise.disable_recording"] = b.disableRecording.toString()
        s["enterprise.unattended_tier"] = b.unattendedTier
        b.pinnedVersion?.let { s["update.pinned_version"] = it }
        b.updateDeferUntilMillis?.let { s["update.defer_until"] = it.toString() }
        for (key in io.agenticcontrol.app.enterprise.PolicyFeatures.ALL) {
            s["feature.$key"] = if (key in b.disabled) "false" else "true"
            if (key in b.required) s["feature.$key.required"] = "true"
        }
        // W12-DS P7-F7: stable id per scope, version in Revision
        // (as Windows) — the old ":vN" id gave each bundle version
        // an independent history, so a stale bundle could win.
        return ManagementPolicyDocument("enterprise-bundle:${b.scopeId}",
            PolicyLevels.ORG, b.scopeId, s, b.version.toLong())
    }
}

/**
 * The on-device receipt path for RMM-07 documents: a document
 * arrives ONLY inside an RMM-03 envelope of class policy_delivery,
 * verified through the gate BEFORE parsing; every application and
 * refusal is a chained audit event. No gate ⇒ named refusal.
 */
class ManagementPolicyReceipt(
    private val engine: ManagementPolicyEngine,
    private val gate: SignedCommandGate?,
    private val audit: ChainedAuditLog,
    /** bd-and-rmm F2: this device's facts + the Effective Policy
     *  store. When supplied, EVERY application or refusal re-binds
     *  PolicyGate (so module policy objects follow the engine) and
     *  re-renders + saves the Effective Policy — the old receipt
     *  never called EffectivePolicyStore.save, so the on-device
     *  view claimed "no policy received" forever. */
    private val factsProvider: (() -> DeviceFacts)? = null,
    private val effectiveStore: EffectivePolicyStore? = null
) {
    private fun afterVerdict() {
        val facts = factsProvider?.invoke() ?: return
        PolicyGate.bind(engine, facts)
        if (effectiveStore != null) {
            try {
                effectiveStore.save(EffectivePolicyView.render(engine, facts))
            } catch (e: Exception) {
                // W12-DS P7-F20: a failed render/save is AUDITED,
                // never swallowed silently — the on-device view is
                // stale and the record says so. The verdict stands.
                try { audit.append("policy_view_stale", "system", "effective policy view save failed: ${e.javaClass.simpleName}", System.currentTimeMillis()) } catch (_: Exception) {}
            }
        }
    }

    fun applySignedDocument(envelope: SignedCommandEnvelope?, actor: String, nowMs: Long): PolicyVerdict {
        if (gate == null) {
            val r = "no signed-command gate configured — policy delivery refuses (RMM-03 coverage is not claimed)"
            audit.append("policy_refusal", actor, r, nowMs); afterVerdict(); return PolicyVerdict(false, r)
        }
        val v = gate.authorize(envelope, nowMs, SignedCommandClasses.POLICY_DELIVERY)
        if (!v.allowed) {
            audit.append("policy_refusal", actor, "signed delivery refused: ${v.reason}", nowMs)
            afterVerdict()
            return PolicyVerdict(false, "signed delivery refused: ${v.reason}")
        }
        val doc = ManagementPolicyDocument.fromCanonicalJson(String(v.payload!!, Charsets.UTF_8))
            ?: run { audit.append("policy_refusal", actor, "policy payload unparseable — refused", nowMs)
                afterVerdict()
                return PolicyVerdict(false, "policy payload unparseable — refused") }
        val verdict = engine.addDocument(doc)
        audit.append(if (verdict.allowed) "policy_applied" else "policy_refusal", actor, verdict.reason, nowMs)
        afterVerdict()
        return verdict
    }

    fun admitLocalDocument(doc: ManagementPolicyDocument, actor: String, nowMs: Long): PolicyVerdict {
        val verdict = engine.addDocument(doc)
        audit.append(if (verdict.allowed) "policy_applied" else "policy_refusal", actor, verdict.reason, nowMs)
        afterVerdict()
        return verdict
    }
}

/** The honest functional Effective Policy surface (model/render
 *  half): every effective setting with provenance, every registry
 *  toggle with its resolved state, and the consent-floor line
 *  stated plainly. The Android Activity renders exactly this text. */
object EffectivePolicyView {

    /** W10 (V3-F4): the setter in OWNER WORDS (record §4 A8:
     *  "… · set by Northwind IT"). The raw provenance (level, doc
     *  id like "enterprise-bundle:<scope>:v3") is an audit fact,
     *  not something the owner reads: an org document is set by
     *  that organisation's IT, a group document by the group's
     *  policy, a device document by this device's own policy. */
    fun setterWords(e: EffectiveSetting): String = when (e.sourceLevel) {
        PolicyLevels.ORG -> "${e.sourceTargetId} IT"
        PolicyLevels.GROUP -> "the ${e.sourceTargetId} group policy"
        PolicyLevels.DEVICE -> "this device's own policy"
        else -> "${e.sourceTargetId} IT"
    }

    /** W10 (V3-F4): one owner-words sentence per rule (§4 A8) —
     *  the registry description IS the owner-words name of the
     *  feature; the sentence states it and its state. Never a raw
     *  key ("rmm.camera_viewing.enabled = true" is not a
     *  sentence an owner can act on). */
    fun toggleSentence(t: FeatureToggle, enabled: Boolean): String =
        "${t.description} — ${if (enabled) "on" else "off"}."

    /** W8 item 4 + W10 (V3-F4): the receipt's per-rule rules, as
     *  model rules. Every rule carries its owner-words sentence +
     *  setter in owner words (null setter = registry default, a
     *  local fact with no attribution), and the surface renders
     *  each one through
     *  [io.agenticcontrol.app.design.EffectivePolicyModel.ruleLine]
     *  — the receipt text is REGENERATED on-device from the live
     *  engine, never pre-rendered text carried in a document.
     *  Status by exception (W10): a rule needs attention when a
     *  document's effective value DIFFERS from the registry
     *  default — in EITHER direction. The old rule flagged only a
     *  default-ON toggle turned OFF, so a policy silently turning
     *  ON default-OFF features with presence/privacy weight
     *  (backstage, background tools, camera viewing, MDM, DLP)
     *  was buried among ~40 ordinary rows. */
    fun rules(
        engine: ManagementPolicyEngine, facts: DeviceFacts
    ): List<io.agenticcontrol.app.design.EffectivePolicyModel.Rule> {
        val eff = engine.computeEffective(facts)
        val out = mutableListOf<io.agenticcontrol.app.design.EffectivePolicyModel.Rule>()
        for (t in engine.registry.all()) {
            val e = eff.get(t.key)
            val enabled = engine.isEnabled(facts, t.key)
            out += io.agenticcontrol.app.design.EffectivePolicyModel.Rule(
                sentence = toggleSentence(t, enabled),
                setter = if (e != null) setterWords(e) else null,
                needsAttention = e != null && enabled != t.defaultEnabled
            )
        }
        val registryKeys = engine.registry.all().map { t -> t.key }.toSet()
        for (s in eff.settings.values.filter { it.key !in registryKeys }.sortedBy { it.key }) {
            out += io.agenticcontrol.app.design.EffectivePolicyModel.Rule(
                sentence = "${s.key} = ${s.value}",
                setter = setterWords(s),
                needsAttention = false
            )
        }
        return out
    }

    /** W10 (V3-F4): the consent floor, rendered ONCE — the title
     *  plus all four A3 items, from EffectivePolicyModel, never
     *  attributed to a setter. The policy render body below
     *  carries NO floor text: the surface shows this box above
     *  the rules, and the floor appears exactly once on screen.
     *  (The old render body carried a second, three-item floor
     *  line — passwords missing — between the member groups and
     *  the rules.) */
    fun floorText(): String = buildString {
        appendLine(io.agenticcontrol.app.design.EffectivePolicyModel.consentFloorTitle())
        for (item in io.agenticcontrol.app.design.EffectivePolicyModel.CONSENT_FLOOR_ITEMS) {
            appendLine("· $item")
        }
    }.trimEnd()

    fun render(engine: ManagementPolicyEngine, facts: DeviceFacts): String {
        val eff = engine.computeEffective(facts)
        val sb = StringBuilder()
        sb.appendLine("Effective Policy — device ${facts.deviceId} (scope ${facts.scopeId})")
        sb.appendLine("Member groups: ${if (eff.memberGroupIds.isEmpty()) "(none)" else eff.memberGroupIds.joinToString(", ")}")
        sb.appendLine("— Rules (status by exception; each line regenerated through the on-device rule line) —")
        // Status by exception ordering, then ruleLine per rule —
        // the same rendering the Activity performs live.
        for (rule in io.agenticcontrol.app.design.EffectivePolicyModel
            .orderByException(rules(engine, facts))) {
            sb.appendLine(io.agenticcontrol.app.design.EffectivePolicyModel.ruleLine(rule))
        }
        return sb.toString()
    }
}

/** File-backed store for the last rendered Effective Policy text,
 *  so the on-device view shows what actually governs this phone
 *  (or says plainly that no policy has been received). */
class EffectivePolicyStore(private val file: File) {
    fun save(text: String) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) { tmp.delete(); throw IllegalStateException("effective policy store rename failed") }
    }
    fun load(): String? = if (file.exists()) file.readText() else null
}
