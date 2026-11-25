package io.agenticcontrol.app.adb

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/**
 * The AndroidKeyStore-backed ADB identity (0.4.0): generated once,
 * kept under the alias "adb_identity", with a self-signed
 * certificate (the Keystore mints it from the generation spec) for
 * the TLS channels. SHA-1 is among the allowed digests because the
 * ADB AUTH signature is SHA1withRSA by protocol definition.
 *
 * bd-and-ui F2 fix (2026-11-22): TLS 1.3 client authentication
 * signs CertificateVerify with RSA-PSS — a key generated with
 * PKCS#1 padding ONLY (the old spec) makes the Keystore refuse
 * that signature, so pairing and TLS connect both failed. The
 * generation spec now allows BOTH paddings (PKCS#1 is still
 * required for the SHA1withRSA AUTH signature) and SHA-512 for
 * PSS. Keys minted under the old spec keep the restriction
 * forever, so [getOrCreate] MIGRATES: an existing key whose spec
 * lacks PSS is deleted and re-created. Migration invalidates the
 * device's trust in the old key — the user must re-pair (the
 * shell section's pairing flow), which the pairing UI surfaces
 * as a failed first connect until re-paired. That is the honest
 * cost; silently keeping a key that cannot do TLS 1.3 was worse.
 */
class AndroidAdbIdentity private constructor(
    private val keyStore: KeyStore,
    override val rsaPublicKey: RSAPublicKey,
    private val privateKey: PrivateKey,
    private val certificate: X509Certificate
) : AdbIdentity {

    override fun signToken(token: ByteArray): ByteArray =
        AdbKey.signToken(privateKey, token)

    override fun sslContext(): SSLContext {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, null)
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        return SSLContext.getInstance("TLSv1.3").apply {
            init(kmf.keyManagers, trustAll, null)
        }
    }

    /** The certificate chain for TLS client auth, PEM-free. */
    fun certificateChain(): Array<X509Certificate> = arrayOf(certificate)

    companion object {
        private const val ALIAS = "adb_identity"

        /** True when the stored key's spec allows RSA-PSS (the
         *  F2 test): a pre-fix key answers false and is migrated. */
        private fun keyAllowsPss(keyStore: KeyStore): Boolean {
            return try {
                val entry = keyStore.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return false
                val factory = java.security.KeyFactory.getInstance(
                    entry.privateKey.algorithm, "AndroidKeyStore")
                val info = factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
                info.signaturePaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            } catch (e: Exception) {
                false // an unreadable spec is treated as pre-fix: migrate
            }
        }

        fun getOrCreate(): AndroidAdbIdentity {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(ALIAS) && !keyAllowsPss(keyStore)) {
                // F2 migration: delete the PKCS#1-only key; the
                // fresh key below replaces it and the user re-pairs.
                try { keyStore.deleteEntry(ALIAS) } catch (_: Exception) {}
            }
            if (!keyStore.containsAlias(ALIAS)) {
                val generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
                )
                val now = System.currentTimeMillis()
                generator.initialize(
                    KeyGenParameterSpec.Builder(
                        ALIAS,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                    )
                        .setKeySize(2048)
                        .setDigests(
                            KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512)
                        .setSignaturePaddings(
                            KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                            KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                        .setCertificateSubject(X500Principal("CN=Agentic Control"))
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setCertificateNotBefore(Date(now - 60_000))
                        .setCertificateNotAfter(Date(now + 20L * 365 * 24 * 3600 * 1000))
                        .build()
                )
                generator.generateKeyPair()
            }
            val entry = keyStore.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
            return AndroidAdbIdentity(
                keyStore,
                entry.certificate.publicKey as RSAPublicKey,
                entry.privateKey,
                entry.certificate as X509Certificate
            )
        }
    }
}
