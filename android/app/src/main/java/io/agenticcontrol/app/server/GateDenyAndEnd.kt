package io.agenticcontrol.app.server

/**
 * W7 item 2 — the gate's third exit (design record §3): "Deny and
 * end session" must ACTUALLY end the session, not just refuse the
 * one action. Every gate call site (AccessToolHost, ShellToolHost,
 * OwedToolHost, and Agent-chat asks) passes this handler as the
 * ApprovalOverlay's onDenyAndEnd: the session is torn down through
 * SessionManager.end() — the same teardown path as every other
 * session end (generation bump, listeners, session_ended event),
 * so presence clears and no tool from the ended generation can
 * proceed.
 *
 * W10 (V3-F1): the handler performs the TEARDOWN ONLY. It used to
 * also emit approval_deny_and_end, and the overlay emitted it a
 * second time — a double audit write — and the overlay emitted
 * even when the handler threw, so the audit could claim an end
 * that never happened. Now the overlay is the single emitter: it
 * invokes this handler, and only when the handler returns does it
 * write approval_deny_and_end, exactly once. A handler exception
 * propagates to the overlay, which writes
 * approval_deny_and_end_failed instead and still dismisses as a
 * deny (fail closed).
 */
object GateDenyAndEnd {

    /** Build the onDenyAndEnd callback for one gate. [endSession]
     *  is injectable so the JVM fixture can prove the teardown
     *  runs (and that a throwing teardown propagates) without an
     *  Android runtime. */
    fun handler(
        actionClass: ApprovalGate.ActionClass,
        endSession: () -> Unit = { SessionManager.end() }
    ): () -> Unit = {
        // actionClass is carried for call-site symmetry with the
        // other gate wiring; the audit event (written by the
        // overlay, with the class) is not this handler's job.
        @Suppress("UNUSED_EXPRESSION") actionClass
        endSession()
    }
}
