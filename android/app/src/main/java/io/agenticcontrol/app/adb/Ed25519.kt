package io.agenticcontrol.app.adb

import java.math.BigInteger

/**
 * Edwards25519 arithmetic (0.4.0), implemented from RFC 8032 §5
 * reference formulas over BigInteger — no native code, no external
 * dependencies. This exists for the SPAKE25519 pairing exchange
 * (adb/Spake25519.kt), which needs point addition, subtraction, and
 * scalar multiplication with the fixed M/N points.
 *
 * Points are extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
 * T = XY/Z. Encoding/decoding follow RFC 8032: 32-byte little-endian
 * y with the sign of x in the top bit.
 *
 * Validation anchors (tests/AdbCryptoTest.kt): the base point and
 * scalarmult are checked against RFC 8032 §7.1 vectors, and the
 * SPAKE M/N points against the encodings published in BoringSSL's
 * spake25519.cc header comment.
 */
object Ed25519 {

    val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    /** The group order L = 2^252 + 27742317777372353535851937790883648493. */
    val L: BigInteger = BigInteger.ONE.shiftLeft(252)
        .add(BigInteger("27742317777372353535851937790883648493"))

    /** d = -121665/121666 mod p (computed, never transcribed). */
    val D: BigInteger = run {
        val numerator = BigInteger.valueOf(-121665).mod(P)
        numerator.multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    }

    /** 2d, used by the addition formula. */
    private val D2: BigInteger = D.multiply(BigInteger.TWO).mod(P)

    /** sqrt(-1) mod p = 2^((p-1)/4) mod p, for point decoding. */
    private val SQRT_M1: BigInteger =
        BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

    data class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger) {
        fun affineX(): BigInteger = x.multiply(z.modInverse(P)).mod(P)
        fun affineY(): BigInteger = y.multiply(z.modInverse(P)).mod(P)
    }

    val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    /** The base point, decoded from its canonical encoding. */
    val BASE: Point = decode(
        hexToBytes("5866666666666666666666666666666666666666666666666666666666666666")
    ) ?: error("base point encoding must decode")

    /** SPAKE25519's M and N, from the coordinates published in
     *  BoringSSL's spake25519.cc (generated from the seeds
     *  'edwards25519 point generation seed (M)' / '(N)'). */
    val POINT_M: Point = pointFromAffine(
        BigInteger("31406539342727633121250288103050113562375374900226415211311216773867585644232"),
        BigInteger("21177308356423958466833845032658859666296341766942662650232962324899758529114")
    )
    val POINT_N: Point = pointFromAffine(
        BigInteger("49918732221787544735331783592030787422991506689877079631459872391322455579424"),
        BigInteger("54629554431565467720832445949441049581317094546788069926228343916274969994000")
    )

    fun pointFromAffine(x: BigInteger, y: BigInteger): Point =
        Point(x.mod(P), y.mod(P), BigInteger.ONE, x.multiply(y).mod(P))

    private fun add(p1: Point, p2: Point): Point {
        // RFC 8032 reference addition for a = -1.
        val a = p1.y.subtract(p1.x).multiply(p2.y.subtract(p2.x)).mod(P)
        val b = p1.y.add(p1.x).multiply(p2.y.add(p2.x)).mod(P)
        val c = p1.t.multiply(D2).multiply(p2.t).mod(P)
        val d = p1.z.multiply(BigInteger.TWO).multiply(p2.z).mod(P)
        val e = b.subtract(a).mod(P)
        val f = d.subtract(c).mod(P)
        val g = d.add(c).mod(P)
        val h = b.add(a).mod(P)
        return Point(
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P)
        )
    }

    private fun double(p1: Point): Point {
        // RFC 8032 reference doubling for a = -1.
        val a = p1.x.multiply(p1.x).mod(P)
        val b = p1.y.multiply(p1.y).mod(P)
        val c = BigInteger.TWO.multiply(p1.z.multiply(p1.z)).mod(P)
        val d = a.negate().mod(P)
        val e = p1.x.add(p1.y).let { it.multiply(it) }.subtract(a).subtract(b).mod(P)
        val g = d.add(b).mod(P)
        val f = g.subtract(c).mod(P)
        val h = d.subtract(b).mod(P)
        return Point(
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P)
        )
    }

    fun addPoints(p1: Point, p2: Point): Point = add(p1, p2)

    fun negate(p1: Point): Point =
        Point(p1.x.negate().mod(P), p1.y, p1.z, p1.t.negate().mod(P))

    fun subtract(p1: Point, p2: Point): Point = add(p1, negate(p2))

    /** scalar * point, scalar as a non-negative integer. */
    fun scalarmult(point: Point, scalar: BigInteger): Point {
        var result = IDENTITY
        var addend = point
        var s = scalar
        while (s > BigInteger.ZERO) {
            if (s.testBit(0)) result = add(result, addend)
            addend = double(addend)
            s = s.shiftRight(1)
        }
        return result
    }

    fun scalarmultBase(scalar: BigInteger): Point = scalarmult(BASE, scalar)

    /**
     * True when [point] has small order (its order divides the
     * cofactor 8): [8]P is the identity. Used to reject small-order
     * public keys / R values in Ed25519 verification (D38 S1-AND
     * F5) — a small-order A makes [k]A public-knowledge and the
     * identity point accepts universal forgeries.
     */
    fun isSmallOrder(point: Point): Boolean =
        encode(scalarmult(point, BigInteger.valueOf(8))).contentEquals(encode(IDENTITY))

    /** RFC 8032 encoding: little-endian y, sign of x in the top bit. */
    fun encode(point: Point): ByteArray {
        val x = point.affineX()
        val y = point.affineY()
        val out = intToLittleEndian(y, 32)
        if (x.testBit(0)) out[31] = (out[31].toInt() or 0x80).toByte()
        return out
    }

    /** Decode a 32-byte encoding; null when it is not a valid point. */
    fun decode(bytes: ByteArray): Point? {
        if (bytes.size != 32) return null
        val sign = (bytes[31].toInt() and 0x80) != 0
        val yBytes = bytes.copyOf()
        yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
        val y = littleEndianToInt(yBytes)
        if (y >= P) return null
        // x = sqrt((y^2 - 1) / (d y^2 + 1)), p = 5 mod 8 method.
        val yy = y.multiply(y).mod(P)
        val u = yy.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(yy).add(BigInteger.ONE).mod(P)
        val xx = u.multiply(v.modInverse(P)).mod(P)
        var x = xx.modPow(P.subtract(BigInteger.valueOf(5)).shiftRight(3), P)
        // x = (u v^3) (u v^7)^((p-5)/8) — the modPow above computes
        // xx^((p-5)/8); multiply by xx to reach the RFC form.
        x = x.multiply(xx).mod(P)
        val vx2 = v.multiply(x.multiply(x)).mod(P)
        when {
            vx2 == u -> Unit
            vx2 == u.negate().mod(P) -> x = x.multiply(SQRT_M1).mod(P)
            else -> return null
        }
        if (x == BigInteger.ZERO && sign) return null
        if (x.testBit(0) != sign) x = P.subtract(x)
        return pointFromAffine(x, y)
    }

    /**
     * BoringSSL's x25519_sc_reduce: interpret 64 little-endian bytes
     * as an integer and reduce mod L, returning 32 little-endian
     * bytes.
     */
    fun scReduce(bytes64: ByteArray): ByteArray {
        require(bytes64.size == 64)
        val reduced = littleEndianToInt(bytes64).mod(L)
        return intToLittleEndian(reduced, 32)
    }

    /** A 32-byte little-endian scalar as an integer. */
    fun littleEndianToInt(bytes: ByteArray): BigInteger {
        val reversed = bytes.reversedArray()
        return BigInteger(1, reversed)
    }

    fun intToLittleEndian(value: BigInteger, length: Int): ByteArray {
        val out = ByteArray(length)
        var v = value
        for (i in 0 until length) {
            out[i] = v.and(BigInteger.valueOf(0xFF)).toByte()
            v = v.shiftRight(8)
        }
        return out
    }

    fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
