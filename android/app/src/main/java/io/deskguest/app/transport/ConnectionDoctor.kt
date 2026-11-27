package io.deskguest.app.transport

/**
 * U6 — Connection doctor, Android mirror of the Windows
 * DeskGuest.Shared.Connection.ConnectionDoctor (same report shape).
 *
 * Answers "why can't I connect?" from facts the app already has.
 * DIAGNOSTIC ONLY, by construction:
 *  - No sockets, no pings, no STUN, no DNS: this file performs no
 *    network I/O at all. It classifies address STRINGS it is handed.
 *  - No mutation: inputs are immutable snapshots; the doctor holds
 *    no reference to any rung, store, or settings it could change.
 *  - No target parameter: a peer address may be CLASSIFIED (parsed,
 *    never contacted) only when already known from enrollment or
 *    discovery.
 *  - Honest verdicts: a rung is "reachable" ONLY on positive
 *    evidence (a recorded successful attempt). Configured / dormant
 *    is never reported as healthy.
 *  - NAT depth honesty: without an owner-configured external
 *    endpoint, upstream NAT depth is unobservable from this device;
 *    the report says so instead of guessing.
 */

enum class AddressClass { NOT_AN_ADDRESS, LOOPBACK, LINK_LOCAL, PRIVATE_RFC1918, TAILNET_CGNAT, CARRIER_GRADE_NAT, PUBLIC, IPV6_GLOBAL, IPV6_PRIVATE_OR_LOCAL, IPV6_OTHER }

enum class NatClass { UNKNOWN, PUBLIC_DIRECT, BEHIND_NAT, CARRIER_GRADE_NAT, DOUBLE_NAT, HOSTILE }

enum class RungState { REACHABLE, CONFIGURED, DORMANT, FAILED, NOT_CONFIGURED, NOT_REGISTERED }

data class DoctorFinding(val what: String, val why: String, val fix: String)

data class RungReport(
    val rung: String, val state: RungState, val evidence: String,
    val finding: DoctorFinding?, val isD18Corner: Boolean
)

/** Immutable snapshot of one rung, taken by the caller from state it
 *  already owns (rung attempt counters, recorded engine events). */
data class RungSnapshot(
    val id: String,
    val registered: Boolean,
    val configured: Boolean,
    val connectAttempts: Int,
    val lastAttemptDetail: String? = null,
    val lastAttemptSucceeded: Boolean = false,
    val laneBound: Boolean = false,
    val lanePhaseName: String? = null,
    val laneAddress: String? = null
)

data class DoctorFacts(
    val localAddresses: List<String>,
    val rungs: List<RungSnapshot>,
    val peerAddress: String? = null,
    val peerNat: NatClass = NatClass.UNKNOWN,
    val wanAddress: String? = null,
    val hasUserOwnedRelay: Boolean = false,
    val tailnetAddresses: Set<String> = emptySet()
)

data class DoctorReport(
    val localNat: NatClass,
    val localAddressClass: AddressClass,
    val peerNat: NatClass,
    val isD18Corner: Boolean,
    val natNote: String,
    val rungs: List<RungReport>,
    val findings: List<DoctorFinding>,
    val summary: String
)

object ConnectionDoctor {

    const val D18_EXPLANATION =
        "This is the D18 exception: both ends sit behind hostile NATs (carrier-grade or symmetric) " +
        "and no user-owned node exists to relay. DeskGuest does not guarantee a relay in this corner — " +
        "it is one of the five named D18 exceptions, not a bug and not a setting you missed."

    fun classifyAddress(text: String?): AddressClass {
        if (text.isNullOrBlank()) return AddressClass.NOT_AN_ADDRESS
        var host = text.trim()
        if (host.startsWith("[") && host.contains(']')) host = host.substring(1, host.indexOf(']'))
        else if (host.count { it == ':' } == 1) host = host.substring(0, host.indexOf(':'))
        if (host.contains(':')) {
            // IPv6 literal (parse-only classification by prefix shape)
            val lower = host.lowercase()
            return when {
                lower == "::1" -> AddressClass.LOOPBACK
                lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb") -> AddressClass.LINK_LOCAL
                lower.startsWith("fc") || lower.startsWith("fd") -> AddressClass.IPV6_PRIVATE_OR_LOCAL
                lower.first() in '2'..'3' -> AddressClass.IPV6_GLOBAL
                else -> AddressClass.IPV6_OTHER
            }
        }
        val parts = host.split('.').map { it.toIntOrNull() ?: return AddressClass.NOT_AN_ADDRESS }
        if (parts.size != 4 || parts.any { it !in 0..255 }) return AddressClass.NOT_AN_ADDRESS
        val (a, b) = parts
        return when {
            a == 127 -> AddressClass.LOOPBACK
            a == 169 && b == 254 -> AddressClass.LINK_LOCAL
            a == 100 && b in 64..127 -> AddressClass.CARRIER_GRADE_NAT
            a == 10 || (a == 172 && b in 16..31) || (a == 192 && b == 168) -> AddressClass.PRIVATE_RFC1918
            else -> AddressClass.PUBLIC
        }
    }

    fun classifyNat(localAddresses: List<String>, wanAddress: String? = null, tailnetAddresses: Set<String> = emptySet()): NatClass {
        val classes = localAddresses.map {
            if (it in tailnetAddresses) AddressClass.TAILNET_CGNAT else classifyAddress(it)
        }.filter { it != AddressClass.NOT_AN_ADDRESS && it != AddressClass.LOOPBACK && it != AddressClass.LINK_LOCAL }
        if (classes.isEmpty()) return NatClass.UNKNOWN
        if (AddressClass.PUBLIC in classes || AddressClass.IPV6_GLOBAL in classes) return NatClass.PUBLIC_DIRECT
        if (AddressClass.CARRIER_GRADE_NAT in classes) return NatClass.CARRIER_GRADE_NAT
        val wan = if (wanAddress == null) AddressClass.NOT_AN_ADDRESS else classifyAddress(wanAddress)
        if (wan == AddressClass.PRIVATE_RFC1918 || wan == AddressClass.CARRIER_GRADE_NAT) return NatClass.DOUBLE_NAT
        return NatClass.BEHIND_NAT
    }

    fun isHostileNat(nat: NatClass): Boolean = nat == NatClass.CARRIER_GRADE_NAT || nat == NatClass.HOSTILE

    fun isD18Corner(local: NatClass, peer: NatClass, hasUserOwnedRelay: Boolean, anyRungReachable: Boolean): Boolean =
        isHostileNat(local) && isHostileNat(peer) && !hasUserOwnedRelay && !anyRungReachable

    fun diagnose(facts: DoctorFacts): DoctorReport {
        val localClass = facts.localAddresses.map { classifyAddress(it) }
            .firstOrNull { it != AddressClass.NOT_AN_ADDRESS && it != AddressClass.LOOPBACK }
            ?: AddressClass.NOT_AN_ADDRESS
        val localNat = classifyNat(facts.localAddresses, facts.wanAddress, facts.tailnetAddresses)
        var peerNat = facts.peerNat
        if (peerNat == NatClass.UNKNOWN && facts.peerAddress != null) {
            peerNat = when (classifyAddress(facts.peerAddress)) {
                AddressClass.CARRIER_GRADE_NAT -> NatClass.CARRIER_GRADE_NAT
                AddressClass.PRIVATE_RFC1918 -> NatClass.BEHIND_NAT
                AddressClass.PUBLIC, AddressClass.IPV6_GLOBAL -> NatClass.PUBLIC_DIRECT
                else -> NatClass.UNKNOWN
            }
        }
        val anyReachable = facts.rungs.any { hasPositiveEvidence(it) }
        val d18 = isD18Corner(localNat, peerNat, facts.hasUserOwnedRelay, anyReachable)
        val rungs = facts.rungs.map { reportRung(it, d18) }
        val findings = rungs.mapNotNull { it.finding }.toMutableList()
        if (d18) findings.add(0, DoctorFinding(
            "No path can be guaranteed between these two devices",
            D18_EXPLANATION,
            "Put one end on a reachable network (public address, or a network whose NAT allows inbound mappings), " +
                "or add a user-owned node (for example your own hub) that both ends can reach, then run the doctor again."))
        val summary = when {
            d18 -> "Connection doctor: D18 corner — both ends are behind hostile NATs and no rung has a proven path. " +
                "${rungs.count { it.state == RungState.REACHABLE }} of ${rungs.size} rung(s) proven reachable."
            anyReachable -> "Connection doctor: at least one rung is proven reachable. ${findings.size} thing(s) still need attention."
            else -> "Connection doctor: no rung is proven reachable yet. ${findings.size} finding(s) below say why, in plain language, with the fix for each."
        }
        return DoctorReport(localNat, localClass, peerNat, d18, natNote(localNat), rungs, findings, summary)
    }

    private fun hasPositiveEvidence(r: RungSnapshot): Boolean =
        r.laneBound || (r.connectAttempts > 0 && r.lastAttemptSucceeded)

    private fun reportRung(r: RungSnapshot, d18: Boolean): RungReport {
        if (!r.registered) return RungReport(r.id, RungState.NOT_REGISTERED,
            "named in the transport set but no implementation is registered in this build",
            DoctorFinding("The '${r.id}' path is listed but not available",
                "This build does not contain that transport, so the connection engine skips it every time.",
                "Remove '${r.id}' from the transport set, or use a build that includes it."), false)
        if (hasPositiveEvidence(r)) return RungReport(r.id, RungState.REACHABLE,
            if (r.laneBound) "listener bound on ${r.laneAddress ?: "its lane address"}"
            else "last attempt succeeded: ${r.lastAttemptDetail ?: "connected"}", null, false)
        if (r.connectAttempts > 0) return RungReport(r.id, RungState.FAILED,
            "attempted ${r.connectAttempts} time(s); last result: ${r.lastAttemptDetail ?: "failed"}",
            DoctorFinding("The '${r.id}' path was tried and did not connect", plainReason(r), fixFor(r, d18)), d18)
        if (!r.configured) return RungReport(r.id, RungState.NOT_CONFIGURED,
            "registered but its configuration is missing",
            DoctorFinding("The '${r.id}' path is not set up",
                "DeskGuest knows this transport but the information it needs (an address, a peer, or a setup step) is not in place, so it cannot be tried.",
                "Complete the '${r.id}' setup step, then run the doctor again."), false)
        return RungReport(r.id, if (r.lanePhaseName == null) RungState.CONFIGURED else RungState.DORMANT,
            if (r.lanePhaseName == null) "configured; never attempted yet — reachability is unproven, not confirmed"
            else "lane phase ${r.lanePhaseName}; never attempted — reachability is unproven, not confirmed",
            DoctorFinding("The '${r.id}' path has not been tried yet",
                "Nothing has attempted this path, so the doctor cannot call it working. A path that was never tried is not a healthy path.",
                "Start a connection so this path is attempted, then run the doctor again to see the recorded result."), false)
    }

    private fun plainReason(r: RungSnapshot): String {
        val d = (r.lastAttemptDetail ?: "").lowercase()
        return when {
            d.contains("no address") -> "There is no address to connect to: the device was not discovered and no address was entered by hand."
            d.contains("refused") -> "The other device answered but refused this device's proof of identity — the pairing/enrollment does not match, or it was revoked."
            d.contains("no deskguest challenge") || d.contains("did not speak") -> "Something answered at that address, but it was not DeskGuest — the address or port points at a different service."
            d.contains("no global ipv6") -> "This device has no global IPv6 address, so the IPv6 path cannot start from here."
            r.lanePhaseName == "NoAddress" -> "This device has no address on that network right now (for the tailnet path: Tailscale is not up on this device)."
            r.lanePhaseName == "BindFailed" -> "The address exists but DeskGuest could not listen on it — something else may already be using it, or the address changed mid-start."
            else -> "The attempt failed (${r.lastAttemptDetail ?: "no detail recorded"}). The recorded result is quoted in the evidence line; no more specific cause was observed."
        }
    }

    private fun fixFor(r: RungSnapshot, d18: Boolean): String {
        if (d18) return "See the D18 finding at the top: this failure is the both-ends-hostile-NAT corner."
        val d = (r.lastAttemptDetail ?: "").lowercase()
        return when {
            d.contains("no address") -> "Run discovery on the same network, or enter the device's address by hand (connect-by-address), then try again."
            d.contains("refused") -> "Re-check the pairing on both devices; if the pairing was revoked, pair again from scratch."
            d.contains("did not speak") || d.contains("no deskguest challenge") -> "Check the address and port point at the DeskGuest device you meant, not another service."
            r.lanePhaseName == "NoAddress" -> "Bring that network up on this device (start Tailscale / join the LAN), then run the doctor again."
            r.lanePhaseName == "BindFailed" -> "Check nothing else is listening on DeskGuest's port, then restart DeskGuest so the listener retries."
            else -> "Check both devices are on, DeskGuest is running on the other device, and the address is current; then try the connection again."
        }
    }

    private fun natNote(nat: NatClass): String = when (nat) {
        NatClass.PUBLIC_DIRECT -> "This device has a public address on its own network interface, so no NAT sits in front of it here."
        NatClass.BEHIND_NAT -> "This device sits behind at least one NAT (its own address is private). How many NATs are stacked upstream cannot be seen from this device alone — the doctor does not send STUN or any other outside probe, so it will not guess."
        NatClass.CARRIER_GRADE_NAT -> "This device's address is in the carrier-grade NAT range (100.64.0.0/10) and is not the tailnet: the internet provider is NAT-ing this connection. Inbound connections from the public internet are not expected to arrive."
        NatClass.DOUBLE_NAT -> "Double NAT: this device's address is private AND the WAN-side address reported locally is also private/carrier-grade. Two NAT layers must both allow a path for a direct inbound connection."
        NatClass.HOSTILE -> "This connection's NAT has been reported as symmetric/hostile: port mappings do not stay predictable, so direct paths usually fail."
        NatClass.UNKNOWN -> "No usable network address was found on this device, so its NAT situation cannot be classified."
    }

    /** One-line-per-rung rendering for the existing setup/health
     *  surface (SetupChecks seam in MainActivity): no new screen. */
    fun renderLines(report: DoctorReport): List<String> {
        val lines = mutableListOf(report.summary, "NAT: ${report.natNote}")
        if (report.isD18Corner) lines.add("D18: $D18_EXPLANATION")
        for (r in report.rungs) {
            lines.add("${r.rung}: ${r.state.name.lowercase()} — ${r.evidence}")
            r.finding?.let { lines.add("  Why: ${it.why} Fix: ${it.fix}") }
        }
        return lines
    }

}
