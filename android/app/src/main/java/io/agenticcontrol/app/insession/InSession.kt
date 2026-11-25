package io.agenticcontrol.app.insession

import io.agenticcontrol.app.cameraview.ChainedAudit
import java.security.MessageDigest

/**
 * RMM-21 (Android mirror) — site documentation + credential vault
 * surfaced IN-SESSION, operator side ("at the rack, phone in hand").
 * Read-only viewer + vault surfacing client, bound to the LIVE
 * session and roster rights: no live session, no surface; wrong
 * scope, no surface. Credential discipline: this layer NEVER holds,
 * logs, or returns a raw credential value in any record it writes —
 * vault items surface as metadata + a one-time reveal handle. The
 * reveal path follows the hub contract's shape: fresh re-auth +
 * hash-chained audit entry chained BEFORE the value is released by
 * the hub-side provider (the provider is an interface here; the raw
 * value transits hub->operator over the session channel only and is
 * never persisted by this client).
 */
object InSessionPolicy {
    // bd-and-rmm F2 fix (2026-11-22): keys aligned to the RMM-07
    // registry — docs ride rmm.site_documentation.enabled (the old
    // rmm.site_docs.enabled existed nowhere in the registry), the
    // vault rides the now-registered rmm.vault_surfacing.enabled,
    // and a bound ManagementPolicyEngine governs via PolicyGate.
    @Volatile var docsEnabled: Boolean = true // rmm.site_documentation.enabled
    @Volatile var vaultEnabled: Boolean = true // rmm.vault_surfacing.enabled
    @Volatile var vaultRevealEnabled: Boolean = false // rmm.vault_surfacing.reveal.enabled (default OFF)
    fun isDocsEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.site_documentation.enabled", docsEnabled)
    fun isVaultEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.vault_surfacing.enabled", vaultEnabled)
}

fun interface LiveSessionCheck { fun isLiveSession(sessionId: String, scopeId: String, operatorId: String): Boolean }
fun interface DocRights { fun canReadDocs(scopeId: String, operatorId: String, siteId: String): Boolean }
fun interface VaultRights { fun canSurfaceVault(scopeId: String, operatorId: String, siteId: String): Boolean }
fun interface ReAuthenticator { fun reAuthenticate(operatorId: String, proof: String): Boolean }
fun interface VaultValueProvider { fun fetchValue(itemId: String, revealToken: String): String? }

data class SiteDoc(val id: String, val siteId: String, val scopeId: String, val title: String, val body: String, val updatedMs: Long)
data class VaultItemMeta(val id: String, val siteId: String, val scopeId: String, val label: String, val usernameHint: String, val updatedMs: Long)

class InSessionService(
    private val sessions: LiveSessionCheck,
    private val docRights: DocRights,
    private val vaultRights: VaultRights,
    private val reauth: ReAuthenticator,
    private val provider: VaultValueProvider,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private val docs = mutableMapOf<String, SiteDoc>()
    private val items = mutableMapOf<String, VaultItemMeta>()
    private val revealTokens = mutableMapOf<String, Pair<String, Long>>() // token -> (itemId, expiresMs)
    private var nextToken = 1

    @Synchronized fun registerDoc(doc: SiteDoc) { docs[doc.id] = doc }
    @Synchronized fun registerVaultItem(item: VaultItemMeta) { items[item.id] = item }

    private fun gate(sessionId: String, scopeId: String, operatorId: String, siteId: String, vault: Boolean): String? {
        if (!sessions.isLiveSession(sessionId, scopeId, operatorId)) return "no live session binds this surface"
        if (vault) {
            if (!InSessionPolicy.isVaultEnabled()) return "policy rmm.vault_surfacing.enabled is OFF"
            if (!vaultRights.canSurfaceVault(scopeId, operatorId, siteId)) return "no vault right for this site"
        } else {
            if (!InSessionPolicy.isDocsEnabled()) return "policy rmm.site_documentation.enabled is OFF"
            if (!docRights.canReadDocs(scopeId, operatorId, siteId)) return "no doc right for this site"
        }
        return null
    }

    @Synchronized
    fun listDocs(sessionId: String, scopeId: String, operatorId: String, siteId: String): Result<List<SiteDoc>> {
        gate(sessionId, scopeId, operatorId, siteId, vault = false)?.let {
            audit.append("site_doc_refused", "operator=$operatorId site=$siteId reason=$it"); return Result.failure(IllegalStateException(it))
        }
        val out = docs.values.filter { it.siteId == siteId && it.scopeId == scopeId }
        audit.append("site_doc_listed", "operator=$operatorId site=$siteId count=${out.size}")
        return Result.success(out)
    }
    @Synchronized
    fun readDoc(sessionId: String, scopeId: String, operatorId: String, docId: String): Result<SiteDoc> {
        val doc = docs[docId] ?: return Result.failure(IllegalStateException("unknown doc"))
        gate(sessionId, scopeId, operatorId, doc.siteId, vault = false)?.let {
            audit.append("site_doc_refused", "operator=$operatorId doc=$docId reason=$it"); return Result.failure(IllegalStateException(it))
        }
        if (doc.scopeId != scopeId) return Result.failure(IllegalStateException("cross-scope doc refused"))
        audit.append("site_doc_read", "operator=$operatorId doc=$docId")
        return Result.success(doc)
    }

    /** Metadata only — the returned shape has no value field to leak. */
    @Synchronized
    fun listVault(sessionId: String, scopeId: String, operatorId: String, siteId: String): Result<List<VaultItemMeta>> {
        gate(sessionId, scopeId, operatorId, siteId, vault = true)?.let {
            audit.append("vault_list_refused", "operator=$operatorId site=$siteId reason=$it"); return Result.failure(IllegalStateException(it))
        }
        return Result.success(items.values.filter { it.siteId == siteId && it.scopeId == scopeId })
    }

    /**
     * Reveal: policy -> live session -> right -> RE-AUTH -> audit
     * chained BEFORE the provider is called -> one-time token ->
     * value returned to the caller only (never stored, never logged;
     * the audit records the item id and a hash of nothing secret).
     */
    @Synchronized
    fun reveal(sessionId: String, scopeId: String, operatorId: String, itemId: String, reauthProof: String): Result<String> {
        val item = items[itemId] ?: return Result.failure(IllegalStateException("unknown vault item"))
        if (!InSessionPolicy.vaultRevealEnabled) {
            audit.append("vault_reveal_refused", "operator=$operatorId item=$itemId reason=reveal policy OFF")
            return Result.failure(IllegalStateException("policy rmm.vault_surfacing.reveal.enabled is OFF"))
        }
        gate(sessionId, scopeId, operatorId, item.siteId, vault = true)?.let {
            audit.append("vault_reveal_refused", "operator=$operatorId item=$itemId reason=$it"); return Result.failure(IllegalStateException(it))
        }
        if (item.scopeId != scopeId) return Result.failure(IllegalStateException("cross-scope vault item refused"))
        if (!reauth.reAuthenticate(operatorId, reauthProof)) {
            audit.append("vault_reveal_refused", "operator=$operatorId item=$itemId reason=re-auth failed")
            return Result.failure(IllegalStateException("re-authentication failed"))
        }
        val token = "reveal-${nextToken++}-${clockMs()}"
        revealTokens[token] = itemId to (clockMs() + 30_000)
        audit.append("vault_reveal", "operator=$operatorId item=$itemId tokenHash=${sha(token)}") // BEFORE provider call
        val value = provider.fetchValue(itemId, token)
        revealTokens.remove(token) // one-time: consumed whatever the outcome
        return if (value == null) Result.failure(IllegalStateException("vault provider returned no value"))
        else Result.success(value)
    }
    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
}
