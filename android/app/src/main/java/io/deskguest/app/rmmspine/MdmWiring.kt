package io.deskguest.app.rmmspine

import io.deskguest.app.enterprise.ChainedAuditLog
import java.io.File

/**
 * W8 item 2 — live MdmService wiring. Before this, no MdmService
 * was constructed anywhere in app wiring: RmmNoticesActivity
 * could only re-read the persisted notice file, so the surface
 * and the service were two disconnected halves (and if no
 * service ever wrote the file, the surface honestly showed "No
 * organisation actions have been recorded"). This builder is the
 * ONE construction the app uses (ControlService calls it at
 * startup and publishes the instance as sharedMdmService):
 *
 *  - notices persist to the SAME file the surface reads
 *    (mdm-notices.tsv), so the live in-memory list and the
 *    durable store are one record, not two;
 *  - the executor is the HONEST unavailable one: no platform
 *    DevicePolicyManager executor is bound on this host, so an
 *    action that somehow reached execution would report NOT
 *    executed, by name — never a fake success;
 *  - the signed-command gate is null: MDM actions therefore
 *    refuse at the service wall ("RMM-03 coverage is not
 *    claimed") until a customer key ring is provisioned through
 *    CommandGateWiring. Absent-source honesty is preserved end
 *    to end: no facts provider ⇒ policy gate refuses closed.
 */
object MdmWiring {

    const val NOTICE_FILE_NAME = "mdm-notices.tsv"

    fun build(
        filesDir: File,
        audit: ChainedAuditLog,
        factsFor: (String) -> DeviceFacts? = { null }
    ): MdmService = MdmService(
        engine = ManagementPolicyEngine(),
        gate = null,
        executor = UnavailableMdmActionExecutor(),
        audit = audit,
        factsFor = factsFor,
        noticeStoreFile = File(filesDir, NOTICE_FILE_NAME)
    )

    /** The live service's notices in the surface's render shape:
     *  (commandId, deviceId, kind, noticeText, recordedMs). */
    fun liveNoticeRows(service: MdmService): List<List<String>> =
        service.notices().map { n ->
            listOf(n.commandId, n.deviceId, n.kind, n.noticeText, n.recordedMs.toString())
        }
}
