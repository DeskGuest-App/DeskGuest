package io.deskguest.app.design

/**
 * W10 (V3-F3f) — QR option for pairing (record §4 A2: "Pairing
 * offers QR + code"). A small, dependency-free QR encoder: byte
 * mode, error-correction level M, versions 1–8 (up to 152 data
 * bytes — the pairing offer is ~70 bytes). No third-party library
 * is bundled (the build is offline and library-free by design).
 *
 * Correctness is pinned against an external reference: the JVM
 * fixture (W10V3FixTest) compares this encoder's matrices, module
 * for module, with matrices produced by the segno reference
 * implementation for the same payloads at forced masks — never
 * app-against-itself (the AGENTS.md protocol-math rule).
 *
 * The matrix returned by [encode] excludes the quiet zone; the
 * renderer adds it.
 */
object QrCode {

    /** One encoded symbol: [modules] is size×size, true = dark. */
    data class Symbol(val version: Int, val mask: Int, val size: Int, val modules: Array<BooleanArray>) {
        fun rowStrings(): List<String> = modules.map { row ->
            row.joinToString("") { if (it) "1" else "0" }
        }
    }

    // Level-M structure per version: (ec codewords per block,
    // group1 blocks × data codewords, group2 blocks × data cw).
    private data class Spec(
        val ecPerBlock: Int,
        val g1Blocks: Int, val g1Data: Int,
        val g2Blocks: Int, val g2Data: Int
    ) {
        val dataCodewords: Int get() = g1Blocks * g1Data + g2Blocks * g2Data
        val blocks: Int get() = g1Blocks + g2Blocks
    }

    private val SPECS: Map<Int, Spec> = mapOf(
        1 to Spec(10, 1, 16, 0, 0),
        2 to Spec(16, 1, 28, 0, 0),
        3 to Spec(26, 1, 44, 0, 0),
        4 to Spec(18, 2, 32, 0, 0),
        5 to Spec(24, 2, 43, 0, 0),
        6 to Spec(16, 4, 27, 0, 0),
        7 to Spec(18, 4, 31, 0, 0),
        8 to Spec(22, 2, 38, 2, 39)
    )

    private val ALIGN_CENTERS: Map<Int, IntArray> = mapOf(
        1 to intArrayOf(),
        2 to intArrayOf(6, 18),
        3 to intArrayOf(6, 22),
        4 to intArrayOf(6, 26),
        5 to intArrayOf(6, 30),
        6 to intArrayOf(6, 34),
        7 to intArrayOf(6, 22, 38),
        8 to intArrayOf(6, 24, 42)
    )

    private val REMAINDER_BITS: Map<Int, Int> = mapOf(
        1 to 0, 2 to 7, 3 to 7, 4 to 7, 5 to 7, 6 to 7, 7 to 0, 8 to 0
    )

    // ---- GF(256) with primitive polynomial 0x11D ----
    private val EXP = IntArray(512)
    private val LOG = IntArray(256)

    init {
        var x = 1
        for (i in 0 until 255) {
            EXP[i] = x
            LOG[x] = i
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
        }
        for (i in 255 until 512) EXP[i] = EXP[i - 255]
    }

    private fun gfMul(a: Int, b: Int): Int =
        if (a == 0 || b == 0) 0 else EXP[LOG[a] + LOG[b]]

    /** Reed–Solomon generator polynomial of degree [degree]
     *  (coefficients highest-first, leading 1 omitted in use). */
    private fun rsGenerator(degree: Int): IntArray {
        var poly = intArrayOf(1)
        for (i in 0 until degree) {
            // Multiply by (x + α^i): the x term keeps each
            // coefficient's degree, the α^i term drops it by one.
            val next = IntArray(poly.size + 1)
            for (j in poly.indices) {
                next[j] = next[j] xor poly[j]
                next[j + 1] = next[j + 1] xor gfMul(poly[j], EXP[i])
            }
            poly = next
        }
        return poly
    }

    private fun rsRemainder(data: IntArray, degree: Int): IntArray {
        val gen = rsGenerator(degree)
        val rem = IntArray(degree)
        for (b in data) {
            val factor = b xor rem[0]
            rem.copyInto(rem, 0, 1, rem.size)
            rem[rem.size - 1] = 0
            if (factor != 0) {
                for (i in 0 until degree) rem[i] = rem[i] xor gfMul(gen[i + 1], factor)
            }
        }
        return rem
    }

    /** Encode [text] (UTF-8) at level M, choosing the smallest
     *  fitting version and the lowest-penalty mask. [forceMask]
     *  exists for the reference fixture. Returns null when the
     *  payload exceeds version 8-M capacity. */
    fun encode(text: String, forceMask: Int? = null): Symbol? {
        val bytes = text.toByteArray(Charsets.UTF_8)
        val version = (1..8).firstOrNull { v ->
            val capBits = SPECS.getValue(v).dataCodewords * 8
            4 + 8 + bytes.size * 8 <= capBits
        } ?: return null
        val dataCw = buildDataCodewords(bytes, version)
        val all = interleave(dataCw, version)
        val masks = if (forceMask != null) listOf(forceMask) else (0..7).toList()
        var best: Symbol? = null
        var bestPenalty = Int.MAX_VALUE
        for (mask in masks) {
            val sym = draw(all, version, mask)
            val p = penalty(sym.modules)
            if (p < bestPenalty) {
                bestPenalty = p
                best = sym
            }
        }
        return best
    }

    private fun buildDataCodewords(bytes: ByteArray, version: Int): IntArray {
        val spec = SPECS.getValue(version)
        val capBits = spec.dataCodewords * 8
        val bits = mutableListOf<Int>()
        fun append(value: Int, length: Int) {
            for (i in length - 1 downTo 0) bits.add((value ushr i) and 1)
        }
        append(0b0100, 4) // byte mode
        append(bytes.size, 8) // length (versions 1–9)
        for (b in bytes) append(b.toInt() and 0xFF, 8)
        append(0, minOf(4, capBits - bits.size)) // terminator
        // Byte alignment. The reference implementation (segno,
        // ISO 18004 reader) extends the stream by a full zero
        // byte when it is already aligned and capacity remains —
        // pad content is never parsed by decoders, and matching
        // the reference here is what makes the external fixture
        // bit-exact. When the stream exactly fills the capacity,
        // nothing is added.
        val alignPad = if (bits.size % 8 == 0) 8 else 8 - bits.size % 8
        repeat(minOf(alignPad, capBits - bits.size)) { bits.add(0) }
        val out = mutableListOf<Int>()
        var i = 0
        while (i < bits.size) {
            var v = 0
            for (j in 0 until 8) v = (v shl 1) or bits[i + j]
            out.add(v)
            i += 8
        }
        val pads = intArrayOf(0xEC, 0x11)
        var p = 0
        while (out.size < spec.dataCodewords) {
            out.add(pads[p % 2]); p++
        }
        return out.toIntArray()
    }

    private fun interleave(data: IntArray, version: Int): IntArray {
        val spec = SPECS.getValue(version)
        val blocks = mutableListOf<IntArray>()
        val ecs = mutableListOf<IntArray>()
        var offset = 0
        repeat(spec.g1Blocks) {
            val block = data.copyOfRange(offset, offset + spec.g1Data)
            blocks.add(block); ecs.add(rsRemainder(block, spec.ecPerBlock))
            offset += spec.g1Data
        }
        repeat(spec.g2Blocks) {
            val block = data.copyOfRange(offset, offset + spec.g2Data)
            blocks.add(block); ecs.add(rsRemainder(block, spec.ecPerBlock))
            offset += spec.g2Data
        }
        val out = mutableListOf<Int>()
        val maxData = maxOf(spec.g1Data, spec.g2Data)
        for (i in 0 until maxData) {
            for (b in blocks) if (i < b.size) out.add(b[i])
        }
        for (i in 0 until spec.ecPerBlock) {
            for (e in ecs) out.add(e[i])
        }
        return out.toIntArray()
    }

    private fun draw(codewords: IntArray, version: Int, mask: Int): Symbol {
        val size = 17 + 4 * version
        val mod = Array(size) { BooleanArray(size) }
        val reserved = Array(size) { BooleanArray(size) }
        fun set(x: Int, y: Int, dark: Boolean, reserve: Boolean = true) {
            if (x in 0 until size && y in 0 until size) {
                mod[y][x] = dark
                if (reserve) reserved[y][x] = true
            }
        }
        // Finder patterns + separators.
        fun finder(cx: Int, cy: Int) {
            for (dy in -4..4) for (dx in -4..4) {
                val x = cx + dx; val y = cy + dy
                if (x !in 0 until size || y !in 0 until size) continue
                val dist = maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy))
                set(x, y, dist != 2 && dist != 4)
            }
        }
        finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
        // Timing patterns.
        for (i in 0 until size) {
            if (!reserved[6][i]) set(i, 6, i % 2 == 0)
            if (!reserved[i][6]) set(6, i, i % 2 == 0)
        }
        // Alignment patterns. Skipped only where the centre falls
        // inside a finder zone; patterns centred on a timing line
        // ARE drawn (their modules coincide with the timing there).
        val centers = ALIGN_CENTERS.getValue(version)
        for (cy in centers) for (cx in centers) {
            val inFinderZone = (cx <= 8 && cy <= 8) ||
                (cx >= size - 9 && cy <= 8) || (cx <= 8 && cy >= size - 9)
            if (inFinderZone) continue
            for (dy in -2..2) for (dx in -2..2) {
                val dist = maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy))
                set(cx + dx, cy + dy, dist != 1)
            }
        }
        // Dark module + format-info reservations.
        set(8, size - 8, true)
        for (i in 0..8) {
            if (i != 6) { reserved[8][i] = true; reserved[i][8] = true }
        }
        for (i in 0 until 8) {
            reserved[8][size - 1 - i] = true
            reserved[size - 1 - i][8] = true
        }
        // Version info (versions ≥ 7): two 18-bit blocks.
        if (version >= 7) {
            val bits = versionInfoBits(version)
            for (i in 0 until 18) {
                val dark = ((bits ushr i) and 1) == 1
                set(size - 11 + i % 3, i / 3, dark)
                set(i / 3, size - 11 + i % 3, dark)
            }
        }
        // Data placement (zig-zag, skipping column 6).
        val totalBits = codewords.size * 8 + REMAINDER_BITS.getValue(version)
        var bitIndex = 0
        var upward = true
        var col = size - 1
        while (col > 0) {
            if (col == 6) col--
            val rows = if (upward) (size - 1 downTo 0) else (0 until size)
            for (y in rows) {
                for (dx in 0..1) {
                    val x = col - dx
                    if (reserved[y][x]) continue
                    var dark = false
                    if (bitIndex < codewords.size * 8) {
                        val byte = codewords[bitIndex / 8]
                        dark = ((byte ushr (7 - bitIndex % 8)) and 1) == 1
                    }
                    if (maskApplies(mask, y, x)) dark = !dark
                    mod[y][x] = dark
                    bitIndex++
                }
            }
            col -= 2
            upward = !upward
        }
        check(bitIndex >= totalBits - REMAINDER_BITS.getValue(version)) {
            "QR placement underflow"
        }
        // Format info for (M, mask), placed LSB-first (bit i of
        // the 15-bit value at the i-th position — the standard
        // mapping, as in the reference implementations).
        val format = formatInfoBits(mask)
        fun bit(i: Int): Boolean = ((format ushr i) and 1) == 1
        // First copy: around the top-left finder.
        val positions1 = listOf(
            8 to 0, 8 to 1, 8 to 2, 8 to 3, 8 to 4, 8 to 5, 8 to 7, 8 to 8,
            7 to 8, 5 to 8, 4 to 8, 3 to 8, 2 to 8, 1 to 8, 0 to 8
        )
        for (i in 0 until 15) {
            val (x, y) = positions1[i]
            mod[y][x] = bit(i); reserved[y][x] = true
        }
        // Second copy: split along the other finders.
        for (i in 0 until 8) {
            mod[8][size - 1 - i] = bit(i); reserved[8][size - 1 - i] = true
        }
        for (i in 8 until 15) {
            mod[size - 15 + i][8] = bit(i); reserved[size - 15 + i][8] = true
        }
        mod[size - 8][8] = true; reserved[size - 8][8] = true
        return Symbol(version, mask, size, mod)
    }

    private fun maskApplies(mask: Int, row: Int, col: Int): Boolean = when (mask) {
        0 -> (row + col) % 2 == 0
        1 -> row % 2 == 0
        2 -> col % 3 == 0
        3 -> (row + col) % 3 == 0
        4 -> (row / 2 + col / 3) % 2 == 0
        5 -> (row * col) % 2 + (row * col) % 3 == 0
        6 -> ((row * col) % 2 + (row * col) % 3) % 2 == 0
        7 -> ((row + col) % 2 + (row * col) % 3) % 2 == 0
        else -> false
    }

    /** 15-bit format information for EC level M (bits 00) + mask,
     *  BCH-encoded with generator 0x537 and masked with 0x5412. */
    private fun formatInfoBits(mask: Int): Int {
        val data = mask // level M indicator bits are 00
        var rem = data
        repeat(10) {
            rem = (rem shl 1) xor (if (rem ushr 9 and 1 == 1) 0x537 else 0)
        }
        return ((data shl 10) or rem) xor 0x5412
    }

    /** 18-bit version information, BCH with generator 0x1F25. */
    private fun versionInfoBits(version: Int): Int {
        var rem = version
        repeat(12) {
            rem = (rem shl 1) xor (if (rem ushr 11 and 1 == 1) 0x1F25 else 0)
        }
        return (version shl 12) or rem
    }

    // ---- Mask penalty (ISO 18004 evaluation rules) ----
    private fun penalty(m: Array<BooleanArray>): Int {
        val size = m.size
        var score = 0
        // Rule 1: runs of ≥5 same-colour modules in rows/columns.
        fun runsPenalty(line: BooleanArray): Int {
            var s = 0; var run = 1
            for (i in 1 until line.size) {
                if (line[i] == line[i - 1]) run++
                else { if (run >= 5) s += run - 2; run = 1 }
            }
            if (run >= 5) s += run - 2
            return s
        }
        for (y in 0 until size) score += runsPenalty(m[y])
        for (x in 0 until size) score += runsPenalty(BooleanArray(size) { m[it][x] })
        // Rule 2: 2×2 same-colour blocks.
        for (y in 0 until size - 1) for (x in 0 until size - 1) {
            if (m[y][x] == m[y][x + 1] && m[y][x] == m[y + 1][x] && m[y][x] == m[y + 1][x + 1]) score += 3
        }
        // Rule 3: finder-like patterns.
        val pat1 = booleanArrayOf(true, false, true, true, true, false, true, false, false, false, false)
        val pat2 = booleanArrayOf(false, false, false, false, true, false, true, true, true, false, true)
        fun patternPenalty(line: BooleanArray): Int {
            var s = 0
            for (i in 0..line.size - 11) {
                val window = line.copyOfRange(i, i + 11)
                if (window.contentEquals(pat1) || window.contentEquals(pat2)) s += 40
            }
            return s
        }
        for (y in 0 until size) score += patternPenalty(m[y])
        for (x in 0 until size) score += patternPenalty(BooleanArray(size) { m[it][x] })
        // Rule 4: dark-module proportion.
        var dark = 0
        for (y in 0 until size) for (x in 0 until size) if (m[y][x]) dark++
        val total = size * size
        val k = kotlin.math.ceil(kotlin.math.abs(dark * 20 - total * 10).toDouble() / total).toInt() - 1
        if (k > 0) score += k * 10
        return score
    }
}
