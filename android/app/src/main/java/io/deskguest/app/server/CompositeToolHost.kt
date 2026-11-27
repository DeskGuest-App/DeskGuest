package io.deskguest.app.server

/** Merges several tool hosts into the one host McpCore serves. */
class CompositeToolHost(private vararg val hosts: McpCore.ToolHost) : McpCore.ToolHost {
    override fun tools(): List<McpCore.ToolDef> = hosts.flatMap { it.tools() }

    override fun attach(core: McpCore) {
        hosts.forEach { it.attach(core) }
    }
}
