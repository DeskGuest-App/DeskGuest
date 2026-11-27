import io.deskguest.app.backup.*
import io.deskguest.app.bgtools.*
import io.deskguest.app.camerashare.*
import io.deskguest.app.cameraview.*
import io.deskguest.app.deploy.*
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.insession.*
import io.deskguest.app.mobileop.*
import io.deskguest.app.probes.*
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.vendorpass.*
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/** Lane B3 (Android operator & media) — JVM suite for items 1-8 of the
 *  completion scope, incl. destruction cases DG-B3-*. */
private var failures = 0
private fun check(name: String, cond: Boolean) {
    if (cond) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}
private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

fun main() {
    var now = 1_000_000L
    val clock = { now }

    // ---------- Item 1: roster `view` right (real RosterStore) ----------
    run {
        val dir = Files.createTempDirectory("b3roster").toFile()
        val enroll = EnrollmentStore(File(dir, "e.tsv"))
        val r = RosterStore(File(dir, "r.tsv"), enroll)
        r.addScope(RosterStore.Scope("co", "company", "Co"))
        r.addUser(RosterStore.User("admin", "co", "Admin", "human"))
        r.addCompanyAdmin("co", "admin")
        r.addUser(RosterStore.User("op", "co", "Op", "human"))
        r.addUser(RosterStore.User("ai1", "co", "AI", "ai", pairedByUserId = "admin"))
        r.addUserGroup(RosterStore.UserGroup("ug", "co", "Ops", memberUserIds = setOf("op", "ai1")), "admin")
        r.addDeviceGroup(RosterStore.DeviceGroup("dg", "co", "Cams"), "admin")
        check("B3-1 view grant accepted by roster D12 machinery", r.addGrant(RosterStore.Grant("co", "ug", "dg", setOf("view")), "admin"))
        check("B3-1 human holds view via grant", r.userHasRight("co", "op", "dg", "view"))
        check("B3-1 DG-B3-01 AI holds view ONLY because admin explicitly granted it", r.userHasRight("co", "ai1", "dg", "view"))
        check("B3-1 DG-B3-02 AI still never holds admin (D9)", !r.userHasRight("co", "ai1", "dg", "admin"))
        check("B3-1 unknown right holds nothing", !r.userHasRight("co", "op", "dg", "record"))
        dir.deleteRecursively()
    }

    // ---------- Item 1: camera viewing gate chain ----------
    run {
        CameraViewPolicy.enabled = true; CameraViewPolicy.audioEnabled = false
        var grant = true
        val svc = CameraViewService(ViewRights { _, _, _ -> grant }, ChainedAudit(clock), clock)
        val cam = CameraRecord("cam1", "co", "dg", "192.168.1.50", viewCapability = "rtsp", streamUri = "rtsp://192.168.1.50:554/s")
        check("B3-1 view starts when full chain passes", svc.requestView(cam, "co", "op").isSuccess)
        val id = svc.liveViews().first().id
        check("B3-1 DG-B3-03 non-viewer cannot end another's view", !svc.endView(id, "mallory"))
        check("B3-1 viewer ends own view", svc.endView(id, "op"))
        grant = false
        check("B3-1 DG-B3-04 revoked right refuses live (re-read per view)", svc.requestView(cam, "co", "op").isFailure); grant = true
        CameraViewPolicy.enabled = false
        check("B3-1 policy OFF refuses", svc.requestView(cam, "co", "op").isFailure); CameraViewPolicy.enabled = true
        val cloud = CameraRecord("cam2", "co", "dg", "192.168.1.51", make = "Ring", viewCapability = "inventory_only",
            inventoryReason = CloudCameraClassifier.capabilityFor("Ring", false, false).second)
        val cloudRes = svc.requestView(cloud, "co", "op")
        check("B3-1 cloud-locked camera is inventory-only", cloudRes.isFailure)
        check("B3-1 cloud refusal states the manufacturer's reason", cloudRes.exceptionOrNull()?.message?.contains("Ring") == true)
        check("B3-1 classifier: RTSP-firmware brand camera is viewable (evidence outranks brand)",
            CloudCameraClassifier.capabilityFor("Wyze", false, true).first == "rtsp")
        check("B3-1 DG-B3-05 URI host mismatch (SSRF) refused", svc.requestView(cam.copy(streamUri = "rtsp://192.168.1.99:554/s"), "co", "op").isFailure)
        check("B3-1 DG-B3-06 raw traversal refused", RtspUriGuard.validate("rtsp://192.168.1.50:554/../admin", "192.168.1.50") != null)
        check("B3-1 DG-B3-07 userinfo/query/bad port refused",
            RtspUriGuard.validate("rtsp://u:p@192.168.1.50:554/s", "192.168.1.50") != null &&
            RtspUriGuard.validate("rtsp://192.168.1.50:554/s?x=1", "192.168.1.50") != null &&
            RtspUriGuard.validate("rtsp://192.168.1.50:9999/s", "192.168.1.50") != null)
        check("B3-1 audio without audio policy refuses (no silent downgrade)", svc.requestView(cam, "co", "op", includeAudio = true).isFailure)
        // Flood bound: 50 refused stops collapse
        val before = svc.audit.entries().size
        repeat(50) { svc.endView("nope", "mallory") }
        svc.flushFloodAggregates()
        val added = svc.audit.entries().size - before
        check("B3-1 DG-B3-08 refused-STOP flood is bounded in the chain (added=$added <= 3)", added in 1..3)
        check("B3-1 flood total still recoverable (aggregate count entry present)",
            svc.audit.entries().any { it.type == "camera_stop_refused_aggregate" && it.detail.contains("count=49") })
        check("B3-1 audit chain verifies", svc.audit.verify())
    }

    // ---------- Item 2: RMM-22 camera share ----------
    run {
        CameraSharePolicy.enabled = true; CameraSharePolicy.voiceEnabled = false
        val delivered = mutableListOf<String>(); var torchState = false
        val sink = object : CameraShareSink {
            override fun open(s: String, w: String) { delivered.add("open:$w") }
            override fun deliverFrame(s: String, w: String, f: ByteArray) { delivered.add("frame:$w") }
            override fun deliverAnnotation(s: String, x: Int, y: Int) { delivered.add("ann:$x,$y") }
            override fun setTorch(s: String, on: Boolean) { torchState = on }
            override fun close(s: String, c: String) { delivered.add("close:$c") }
        }
        val parties = object : PartyDirectory {
            override fun isLiveHuman(s: String, u: String) = u in setOf("owner", "watcher")
            override fun isLiveAi(s: String, u: String) = u == "aiw"
            override fun displayName(u: String) = mapOf("owner" to "Owner", "watcher" to "Watcher Wendy", "aiw" to "AI").getOrDefault(u, u)
            override fun phoneFiled(s: String, p: String) = p == "phone1"
            // Added for bd-and-rmm F6 (laneW2-andfix1): the
            // directory now answers phone ownership; "owner" owns
            // phone1, nobody else does.
            override fun isPhoneOwner(s: String, o: String, p: String) = o == "owner" && p == "phone1"
        }
        val svc = CameraShareService(parties, sink, DeskGuestfValidator { it.isNotEmpty() && it[0] == 1.toByte() }, ChainedAudit(clock), clock)
        check("B3-2 DG-B3-09 watcher-side start refuses + audits", svc.requestShareFromWatcher("watcher", "phone1").isFailure &&
            svc.audit.entries().any { it.type == "camera_share_inbound_start_refused" })
        check("B3-2 DG-B3-10 AI cannot initiate", svc.initiateShare("co", "aiw", "phone1", "watcher").isFailure)
        check("B3-2 DG-B3-11 AI watcher without grant refused (default denied)", svc.initiateShare("co", "owner", "phone1", "aiw").isFailure)
        check("B3-2 AI grant mints by live human owner", svc.grantAiWatcher("owner", "co", "aiw", "phone1", 60))
        val aiShare = svc.initiateShare("co", "owner", "phone1", "aiw")
        check("B3-2 AI watcher with live grant may be named", aiShare.isSuccess)
        svc.stopShare(aiShare.getOrThrow().id, "owner")
        val share = svc.initiateShare("co", "owner", "phone1", "watcher").getOrThrow()
        check("B3-2 presence waiting names the watcher", svc.presence(share.id)?.bannerText?.contains("Watcher Wendy") == true)
        check("B3-2 presence STOP available while live", svc.presence(share.id)?.stopAvailable == true)
        check("B3-2 DG-B3-12 frames while waiting are DROPPED, never buffered", !svc.submitFrame(share.id, "owner", byteArrayOf(1, 2)) && svc.share(share.id)?.frameCount == 0L)
        check("B3-2 watcher joins -> sharing", svc.watcherJoin(share.id, "watcher"))
        check("B3-2 frame from owner delivered to named watcher only", svc.submitFrame(share.id, "owner", byteArrayOf(1, 9)) && delivered.contains("frame:watcher"))
        check("B3-2 DG-B3-13 frame from non-owner refused", !svc.submitFrame(share.id, "watcher", byteArrayOf(1, 9)))
        check("B3-2 DG-B3-14 invalid DGSF envelope refused", !svc.submitFrame(share.id, "owner", byteArrayOf(7, 9)))
        check("B3-2 annotation in range forwards", svc.sendAnnotation(share.id, "watcher", 500, 500))
        check("B3-2 DG-B3-15 annotation out of range refused", !svc.sendAnnotation(share.id, "watcher", 1001, 0))
        check("B3-2 voice enable refused while voice policy OFF", !svc.setVoice(share.id, "owner", true))
        check("B3-2 torch is owner-only and binds sink", svc.setTorch(share.id, "owner", true) && torchState && !svc.setTorch(share.id, "watcher", false))
        check("B3-2 recording structurally refused", !svc.tryEnableRecording(share.id) && svc.share(share.id)?.isRecording == false)
        check("B3-2 DG-B3-16 admin/third party cannot STOP someone else's camera", !svc.stopShare(share.id, "watcher"))
        svc.ownerNavigatedAway(share.id)
        check("B3-2 owner navigation away ends share with cause", svc.share(share.id)?.state == "ended" && delivered.contains("close:owner_navigated_away"))
        val s2 = svc.initiateShare("co", "owner", "phone1", "watcher").getOrThrow(); svc.watcherJoin(s2.id, "watcher")
        svc.watcherDisconnect(s2.id)
        check("B3-2 watcher disconnect ends share", svc.share(s2.id)?.state == "ended")
        val s3 = svc.initiateShare("co", "owner", "phone1", "watcher").getOrThrow()
        now += 61 * 60_000; svc.tick()
        check("B3-2 DG-B3-17 Tick timeout ends share", svc.share(s3.id)?.state == "ended"); now -= 61 * 60_000
        check("B3-2 audit chain verifies", svc.audit.verify())
        val fields = CameraShareService.Share::class.java.declaredFields.map { it.name }
        check("B3-2 DG-B3-18 share record holds NO frame bytes (counts only)", fields.none { it.contains("frame", true) && !it.contains("count", true) })
    }

    // ---------- Item 3: RMM-21 in-session ----------
    run {
        InSessionPolicy.vaultRevealEnabled = true
        var live = true; var reauthOk = true; var providerCalls = 0
        val svc = InSessionService(
            LiveSessionCheck { _, _, _ -> live }, DocRights { _, _, _ -> true }, VaultRights { _, _, _ -> true },
            ReAuthenticator { _, _ -> reauthOk },
            VaultValueProvider { _, _ -> providerCalls++; "s3cr3t-value" }, ChainedAudit(clock), clock)
        svc.registerDoc(SiteDoc("d1", "site1", "co", "Rack map", "body", now))
        svc.registerVaultItem(VaultItemMeta("v1", "site1", "co", "JACE login", "admin", now))
        check("B3-3 docs list in live session", svc.listDocs("sess", "co", "op", "site1").getOrThrow().size == 1)
        live = false
        check("B3-3 DG-B3-19 no live session, no surface", svc.listDocs("sess", "co", "op", "site1").isFailure &&
            svc.listVault("sess", "co", "op", "site1").isFailure); live = true
        check("B3-3 vault listing is metadata-only shape", svc.listVault("sess", "co", "op", "site1").getOrThrow().single().label == "JACE login")
        reauthOk = false
        check("B3-3 DG-B3-20 reveal without re-auth refused, provider untouched", svc.reveal("sess", "co", "op", "v1", "bad").isFailure && providerCalls == 0)
        reauthOk = true
        val v = svc.reveal("sess", "co", "op", "v1", "ok")
        check("B3-3 reveal succeeds after re-auth", v.isSuccess && providerCalls == 1)
        check("B3-3 DG-B3-21 raw value NEVER appears in audit", svc.audit.entries().none { it.detail.contains("s3cr3t-value") })
        check("B3-3 reveal audit chained BEFORE provider call (entry exists)", svc.audit.entries().any { it.type == "vault_reveal" })
        InSessionPolicy.vaultRevealEnabled = false
        check("B3-3 reveal policy OFF refuses", svc.reveal("sess", "co", "op", "v1", "ok").isFailure && providerCalls == 1)
        InSessionPolicy.vaultRevealEnabled = true
        check("B3-3 cross-scope doc refused", svc.readDoc("sess", "other", "op", "d1").isFailure)
    }

    // ---------- Item 4: RMM-10 background tools ----------
    run {
        BgToolsPolicy.enabled = true
        val svc = BgToolService(SignedCommandVerifier { env, _ -> env.signature == "good" },
            BgToolExecutor { t, _ -> "ran:$t" }, ChainedAudit(clock), clock)
        // REPAIRED by laneW2-andfix1 (bd-and-rmm F1, 2026-11-22),
        // disclosed: envelopes now carry the REAL canonical
        // tool/args payload hash (BgToolService.canonicalPayload) —
        // the placeholder "h" only passed because the old service
        // verified the caller payload against itself. The supplied
        // payload argument is now empty (= not supplied; the
        // service rebuilds the canonical bytes itself).
        fun env(nonce: String, sig: String = "good", cls: String = "background_tool", exp: Long = now + 60_000, tool: String = "device_info") =
            SignedEnvelope(cls, nonce, exp, BgToolService.payloadHashHex(BgToolService.canonicalPayload(tool, emptyMap())), sig)
        val payload = byteArrayOf()
        check("B3-4 catalogue tool runs under valid envelope", svc.invoke("device_info", emptyMap(), env("n1"), payload).getOrThrow().state == "succeeded")
        check("B3-4 DG-B3-22 nonce replay refused", svc.invoke("device_info", emptyMap(), env("n1"), payload).isFailure)
        check("B3-4 DG-B3-23 bad signature refused", svc.invoke("device_info", emptyMap(), env("n2", sig = "bad"), payload).isFailure)
        check("B3-4 DG-B3-24 expired envelope refused", svc.invoke("device_info", emptyMap(), env("n3", exp = now - 1), payload).isFailure)
        check("B3-4 DG-B3-25 wrong command class refused", svc.invoke("device_info", emptyMap(), env("n4", cls = "session_tool"), payload).isFailure)
        check("B3-4 DG-B3-26 uncatalogued tool refused", svc.invoke("rm_rf", emptyMap(), env("n5"), payload).isFailure)
        check("B3-4 audit shape is bgtool_* distinct from session tools", svc.audit.entries().all { it.type.startsWith("bgtool_") })
        BgToolsPolicy.setToolEnabled("device_info", false)
        check("B3-4 per-tool policy toggle refuses", svc.invoke("device_info", emptyMap(), env("n6"), payload).isFailure)
        BgToolsPolicy.setToolEnabled("device_info", true)
        val flaky = BgToolService(SignedCommandVerifier { e, _ -> e.signature == "good" },
            BgToolExecutor { _, _ -> throw RuntimeException("boom") }, ChainedAudit(clock), clock)
        val job = flaky.invoke("service_restart", emptyMap(), env("m1", tool = "service_restart"), payload).getOrThrow()
        check("B3-4 failure checkpoints (RMM-15 shape)", job.state == "failed_checkpointed")
        check("B3-4 DG-B3-27 resume with replayed nonce refused", flaky.resume(job.id, env("m1"), payload).isFailure)
    }

    // ---------- Item 5: RMM-11 probes ----------
    run {
        check("B3-5 DG-B3-28 loopback/link-local/multicast targets refused",
            TargetGuard.refusal("127.0.0.1") != null && TargetGuard.refusal("169.254.1.1") != null && TargetGuard.refusal("224.0.0.1") != null)
        check("B3-5 LAN target allowed", TargetGuard.refusal("192.168.1.20") == null)
        // Build a GetResponse carrying sysDescr OCTET STRING "Linux switch"
        fun tlv(tag: Int, v: ByteArray) = byteArrayOf(tag.toByte(), v.size.toByte()) + v
        fun intTlv(v: Int) = tlv(0x02, byteArrayOf(v.toByte()))
        val oidBytes = byteArrayOf(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00)
        // REPAIRED by laneW2-andfix1 (bd-and-rmm F4, 2026-11-22),
        // disclosed: the codec now VERIFIES the response request-id
        // against the request, so the fake agent echoes the id from
        // the request packet (as a real agent does) instead of
        // always answering 1.
        fun ridOf(packet: ByteArray): Int {
            var i = 0
            fun len(): Int { var l = packet[i++].toInt() and 0xff; if (l and 0x80 != 0) { val n = l and 0x7f; l = 0; repeat(n) { l = l shl 8 or (packet[i++].toInt() and 0xff) } }; return l }
            fun skip() { i++; val l = len(); i += l }
            i++; len() // top SEQ
            skip(); skip() // version, community
            i++; len() // PDU
            i++; val l = len(); var v = 0; repeat(l) { v = v shl 8 or (packet[i++].toInt() and 0xff) }; return v
        }
        fun respFor(rid: Int): ByteArray {
            val vb = tlv(0x30, tlv(0x06, oidBytes) + tlv(0x04, "Linux switch".toByteArray()))
            val pdu = tlv(0xA2, intTlv(rid) + intTlv(0) + intTlv(0) + tlv(0x30, vb))
            return tlv(0x30, intTlv(1) + tlv(0x04, "public".toByteArray()) + pdu)
        }
        val svc = ProbeService(UdpTransport { _, _, req, _ -> respFor(ridOf(req)) }, ChainedAudit(clock))
        val r = svc.snmpGet("192.168.1.20", "public", intArrayOf(1, 3, 6, 1, 2, 1, 1, 1, 0), "sysDescr")
        check("B3-5 SNMP GET round-trips through BER codec", r.value == "Linux switch")
        check("B3-5 topology classifies from evidence", svc.mapTopology(listOf("192.168.1.20"), "public").single().kind == "network")
        val dead = ProbeService(UdpTransport { _, _, _, _ -> null }, ChainedAudit(clock))
        check("B3-5 DG-B3-29 silent host classifies NOTHING (no fabrication)", dead.mapTopology(listOf("192.168.1.21"), "public").isEmpty() &&
            dead.snmpGet("192.168.1.21", "public", intArrayOf(1, 3, 6, 1, 2, 1, 1, 1, 0), "sysDescr").error?.contains("timeout") == true)
        check("B3-5 blank community never defaulted", svc.snmpGet("192.168.1.20", "", intArrayOf(1, 3), "x").error?.contains("community") == true)
        check("B3-5 ICMP named unavailable, never faked", svc.agentlessCheck("192.168.1.20", "icmp_ping").outcome.startsWith("unavailable"))
        check("B3-5 malformed SNMP response decodes to no value", SnmpCodec.decodeValue(byteArrayOf(1, 2, 3)) == null)
    }

    // ---------- Item 6: RMM-16 deployment ----------
    run {
        DeployPolicy.enabled = true; DeployPolicy.contentPacksEnabled = true
        var handed = false
        val svc = DeployService(SignatureVerifier { _, s -> s == "sig" }, InstallerHandoff { _, _ -> handed = true; true }, ChainedAudit(clock))
        val payload = "apk-bytes".toByteArray(); val unit = DeployUnit("app1", "apk", "2.0", sha(payload))
        check("B3-6 DG-B3-30 APK without user confirmation refused (app-tier bound)", svc.deploy(unit, byteArrayOf(1), "sig", payload, userConfirmed = false).isFailure && !handed)
        check("B3-6 confirmed APK hands to system installer", svc.deploy(unit, byteArrayOf(1), "sig", payload, userConfirmed = true).isSuccess && handed)
        check("B3-6 DG-B3-31 hash mismatch refused", svc.deploy(unit, byteArrayOf(1), "sig", "tampered".toByteArray(), true).isFailure)
        check("B3-6 DG-B3-32 bad manifest signature refused", svc.deploy(unit, byteArrayOf(1), "bad", payload, true).isFailure)
        val packPayload = "fix-a\nfix-b".toByteArray(); val pack = DeployUnit("pack1", "content_pack", "1.0", sha(packPayload))
        check("B3-6 content pack installs over verified machinery", svc.deploy(pack, byteArrayOf(1), "sig", packPayload, false).getOrThrow().contains("2 entries"))
        check("B3-6 surface bound is stated", SURFACE_BOUND.contains("cannot install packages silently"))
    }

    // ---------- Item 7: RMM-23 vendor passes ----------
    run {
        VendorPassPolicy.enabled = true
        var vendorLive = true; var vendorRights = setOf("use", "view")
        val svc = VendorPassService(
            PassRights { _, u, _, right -> if (u == "admin") right == "admin" else right in vendorRights },
            LiveParty { _, _ -> vendorLive }, ChainedAudit(clock), clock)
        val p = svc.issue("co", "admin", "vendor", "dg", setOf("use", "view"), 120).getOrThrow()
        check("B3-7 pass authorizes held right", svc.authorize(p.id, "view"))
        check("B3-7 DG-B3-33 pass carrying admin refused at issue", svc.issue("co", "admin", "vendor", "dg", setOf("admin"), 60).isFailure)
        check("B3-7 DG-B3-34 non-admin cannot issue", svc.issue("co", "vendor", "vendor", "dg", setOf("use"), 60).isFailure)
        vendorRights = setOf("use")
        check("B3-7 DG-B3-35 live roster-right removal kills pass effect", !svc.authorize(p.id, "view")); vendorRights = setOf("use", "view")
        now += 121 * 60_000
        check("B3-7 DG-B3-36 expired pass denies", !svc.authorize(p.id, "view")); now -= 121 * 60_000
        check("B3-7 admin revokes pass", svc.revoke(p.id, "admin") && !svc.authorize(p.id, "view"))
        check("B3-7 browser hardening recorded not-applicable off managed devices", VendorPassPolicy.BROWSER_HARDENING_TIER.startsWith("not_applicable_personal"))
    }

    // ---------- Item 8: RMM-06 backup ----------
    run {
        BackupPolicy.enabled = true
        val dest = object : SafTree {
            val files = mutableMapOf<String, ByteArray>(); var grant = true
            override fun granted() = grant
            override fun write(n: String, b: ByteArray) = true.also { files[n] = b }
            override fun read(n: String) = files[n]
        }
        val svc = BackupService(StoreSource { mapOf("roster.tsv" to "data".toByteArray()) }, ChainedAudit(clock), clock, allowLegacyPlaintext = true) // W12-DS: legacy fixture opts in explicitly
        val m = svc.backup(dest, mapOf("docs" to mapOf("a.txt" to "hello".toByteArray()))).getOrThrow()
        check("B3-8 backup covers DeskGuest stores + SAF-granted folders", m.entries.keys.any { it.startsWith("deskguest/") } && m.entries.keys.any { it.startsWith("saf/docs/") })
        check("B3-8 verify passes on intact backup", svc.verify(dest, m.id).isSuccess)
        val key = dest.files.keys.first { it.endsWith("a.txt") }; dest.files[key] = "evil".toByteArray()
        check("B3-8 DG-B3-37 tampered file refuses whole restore/verify", svc.verify(dest, m.id).isFailure)
        dest.grant = false
        check("B3-8 DG-B3-38 ungranted destination refused (user-owned only)", svc.backup(dest).isFailure)
        BackupPolicy.enabled = false
        check("B3-8 policy OFF (seeded posture) refuses", svc.backup(dest).isFailure); BackupPolicy.enabled = true
    }

    // ---------- Item 9: RMM-24 mobile operator binding ----------
    run {
        MobileOperatorPolicy.enabled = true
        check("B3-9 MobileOnlyRights empty by construction", MOBILE_ONLY_RIGHTS.isEmpty())
        val client = MobileOperatorClient("co", "op",
            RosterRights { _, _, _ -> setOf("use") },
            HubKeyVerifier { _, s -> s == "hubsig" },
            object : ClientKeySigner {
                override fun sign(p: ByteArray) = sha(p + "k".toByteArray())
                override fun verify(p: ByteArray, s: String) = s == sign(p)
            },
            AlertLookup { id -> if (id == "a1") "alert body" else null }, ChainedAudit(clock))
        check("B3-9 capabilities derive from roster rights (absent, not disabled)",
            client.can(Capability.VIEW_DEVICES, "dg") && !client.can(Capability.APPROVE_SESSION, "dg"))
        check("B3-9 presence structural (computed true)", client.presenceVisible)
        check("B3-9 DG-B3-39 platform_push refused BY NAME", client.enqueue("platform_push").exceptionOrNull()?.message?.contains("platform_push") == true)
        check("B3-9 hub alert-id lookup accepted", client.enqueue("hub_alert_lookup", alertId = "a1").isSuccess)
        check("B3-9 DG-B3-40 unknown alert id refused", client.enqueue("hub_alert_lookup", alertId = "nope").isFailure)
        check("B3-9 DG-B3-41 unsigned hub payload refused", client.enqueue("hub_signed", payload = "x".toByteArray(), signature = "bad").isFailure)
        check("B3-9 hub-signed payload accepted", client.enqueue("hub_signed", payload = "x".toByteArray(), signature = "hubsig").isSuccess)
        val adminClient = MobileOperatorClient("co", "boss", RosterRights { _, _, _ -> setOf("use", "admin") },
            HubKeyVerifier { _, s -> s == "hubsig" },
            object : ClientKeySigner {
                override fun sign(p: ByteArray) = sha(p + "k".toByteArray())
                override fun verify(p: ByteArray, s: String) = s == sign(p)
            }, AlertLookup { null }, ChainedAudit(clock))
        val ap = adminClient.approve("content1", "hash1", "dg")!!
        check("B3-9 content-bound approval verifies", adminClient.verifyApproval(ap))
        check("B3-9 DG-B3-42 approval replayed against different content fails", !adminClient.verifyApproval(ap.copy(contentHash = "other")))
    }

    println(if (failures == 0) "ALL LANE B3 TESTS PASSED" else "$failures LANE B3 TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
