package io.agenticcontrol.app.roster

import io.agenticcontrol.app.enrollment.EnrollmentStore

/**
 * Transport-policy resolution (Slice 2, D31/D32) — a pure function
 * over Slice 1's enrollment fields and Slice 2's group record.
 *
 * The unified model (D32): each device group defines an ORDERED
 * transport set chosen from the six automatic rungs; Auto fails over
 * across that set in the group's order; Manual pins to one (or a
 * chosen few) from WITHIN the set; per-device overrides narrow/pin
 * within the set, never outside it. Company policy caps everything
 * (D31 precedence: company ceiling -> group set -> per-device
 * override). Manual WebRTC sits below the chain as a human-invoked
 * last resort and is deliberately NOT one of the six rung ids here.
 */
object TransportPolicy {

    const val RUNG_LAN = "lan"
    const val RUNG_HUB = "hub"
    const val RUNG_MESH = "mesh"
    const val RUNG_IPV6 = "ipv6"
    const val RUNG_OWNPATH = "ownpath"
    const val RUNG_TOR = "tor"

    /** The six automatic rungs (D32), in the D29 default chain order. */
    val RUNGS: List<String> = listOf(RUNG_LAN, RUNG_HUB, RUNG_MESH, RUNG_IPV6, RUNG_OWNPATH, RUNG_TOR)

    /** Normalise an ordered rung list: valid rungs only, duplicates
     *  removed, the caller's order preserved (order is failover
     *  order, D32). */
    fun normalizeOrderedSet(rungs: Collection<String>): List<String> =
        rungs.map { it.trim().lowercase() }.filter { it in RUNGS }.distinct()

    /** True when every id in [rungs] is one of the six rungs. */
    fun isValidSet(rungs: Collection<String>): Boolean =
        rungs.all { it.trim().lowercase() in RUNGS }

    /**
     * D31/D32 resolution: start from the group's ordered set;
     * intersect with the company ceiling ([companyCeiling] == null
     * means no cap — the personal-scope case, D31); then apply the
     * device's Slice 1 fields:
     * - "inherit": the resolved set as-is.
     * - "auto": failover across the resolved set, in its order.
     * - "manual": pin to the device's AllowedTransports, kept in the
     *   RESOLVED set's order (never the pin set's iteration order).
     * A stored pin that names a rung outside the resolved set simply
     * contributes nothing here — the REJECTION of such a pin happens
     * at update time (see [isPinWithinSet] and RosterStore), never by
     * silently widening the resolved set here.
     */
    fun effectiveTransports(
        device: EnrollmentStore.EnrolledDevice,
        groupTransportSet: List<String>,
        companyCeiling: Collection<String>?
    ): List<String> {
        val groupSet = normalizeOrderedSet(groupTransportSet)
        val capped = if (companyCeiling == null) {
            groupSet
        } else {
            val ceiling = companyCeiling.map { it.trim().lowercase() }.toSet()
            groupSet.filter { it in ceiling }
        }
        return when (device.transportMode) {
            EnrollmentStore.TRANSPORT_MODE_MANUAL ->
                // D38 S2-AND F7: Slice 1 defines an empty
                // AllowedTransports as "inherit / none chosen" — a
                // manual record with NO pin chosen resolves to the
                // capped set, never to zero transports (which would
                // silently cut the device off). An explicit pin
                // update with an empty pin is refused at update time
                // in RosterStore; this branch covers records minted
                // directly through Slice 1.
                if (device.allowedTransports.isEmpty()) capped
                else capped.filter { it in device.allowedTransports }
            else -> capped // "auto" and "inherit" both walk the resolved set in order
        }
    }

    /** The resolved set BEFORE the device's own pin is applied —
     *  the set a pin must be a subset of (D32). */
    fun resolvedSet(groupTransportSet: List<String>, companyCeiling: Collection<String>?): List<String> {
        val groupSet = normalizeOrderedSet(groupTransportSet)
        if (companyCeiling == null) return groupSet
        val ceiling = companyCeiling.map { it.trim().lowercase() }.toSet()
        return groupSet.filter { it in ceiling }
    }

    /** D32: a per-device pin is legal only as a subset of the
     *  resolved set. Anything outside is rejected at update time. */
    fun isPinWithinSet(
        pin: Collection<String>,
        groupTransportSet: List<String>,
        companyCeiling: Collection<String>?
    ): Boolean {
        val resolved = resolvedSet(groupTransportSet, companyCeiling).toSet()
        return pin.map { it.trim().lowercase() }.all { it in resolved }
    }
}
