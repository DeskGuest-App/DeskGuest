package io.deskguest.app.access

/**
 * The wait_for match logic (0.4.0), pure so the JVM suite covers it:
 * a condition is an optional package and/or an optional text. It
 * matches when every given part matches — the foreground package
 * equals, and some visible element's label contains the text
 * (case-insensitive). An empty condition never matches: waiting for
 * "anything" is a caller error, not a state.
 */
class WaitCondition(
    val text: String? = null,
    val packageName: String? = null
) {
    val isEmpty: Boolean get() = text.isNullOrBlank() && packageName.isNullOrBlank()

    fun matches(currentPackage: String?, visibleLabels: Collection<String>): Boolean {
        if (isEmpty) return false
        if (!packageName.isNullOrBlank()) {
            if (currentPackage == null || !currentPackage.equals(packageName, ignoreCase = true)) {
                return false
            }
        }
        if (!text.isNullOrBlank()) {
            val needle = text.trim()
            return visibleLabels.any { it.contains(needle, ignoreCase = true) }
        }
        return true
    }
}
