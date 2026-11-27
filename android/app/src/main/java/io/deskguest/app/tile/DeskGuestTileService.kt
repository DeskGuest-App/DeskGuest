package io.deskguest.app.tile

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.deskguest.app.R
import io.deskguest.app.server.ControlService
import io.deskguest.app.strings.consentString
import io.deskguest.app.server.SessionManager

/**
 * Quick Settings tile (0.4.0): the owner's one-tap kill switch and
 * status glance, reachable without opening the app. While a session
 * is live the tile reads "STOP session" and tapping it ends the
 * session on the spot (the same stopByUser path as the overlay STOP).
 * While idle it starts or stops the control channel. The tile only
 * ever reflects state — it never starts a session.
 */
class DeskGuestTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        render()
    }

    override fun onClick() {
        super.onClick()
        when {
            SessionManager.isOpen -> {
                SessionManager.stopByUser()
                render()
            }
            ControlService.sharedServer?.isRunning == true -> {
                ControlService.stop(this)
                render()
            }
            else -> {
                // bd-and-ui F6 fix: STARTING the control channel
                // from the tile is a security-relevant action — it
                // now goes through unlockAndRun, so a locked phone
                // demands the owner's credential first. Stopping
                // (above) never requires unlock: a kill switch that
                // asks for a PIN is not a kill switch. The render
                // happens inside the unlock callback, when the
                // state has actually changed, not optimistically.
                unlockAndRun {
                    ControlService.start(this)
                    render()
                }
            }
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        tile.icon = android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_tile)
        when {
            SessionManager.isPaused -> {
                tile.state = Tile.STATE_ACTIVE
                tile.label = consentString(R.string.tile_paused_label)
                tile.subtitle = consentString(R.string.tile_paused_subtitle)
            }
            SessionManager.isActive -> {
                tile.state = Tile.STATE_ACTIVE
                // F6: an agent in control gets the solid mark —
                // the tile no longer looks identical across states.
                tile.icon = android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_tile_live)
                tile.label = consentString(R.string.tile_stop_label)
                // FR-122: no generic fallback name on a presence
                // surface — a blank driver name shows the defect
                // line, never a fabricated generic ("AI").
                val driverName = SessionManager.active?.agentName?.takeIf { it.isNotBlank() }
                tile.subtitle = if (driverName != null) {
                    consentString(R.string.tile_controlling_subtitle, driverName)
                } else {
                    consentString(R.string.presence_driver_name_missing)
                }
            }
            ControlService.sharedServer?.isRunning == true -> {
                tile.state = Tile.STATE_ACTIVE
                tile.label = consentString(R.string.tile_channel_open_label)
                tile.subtitle = consentString(R.string.tile_channel_open_subtitle)
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                tile.label = consentString(R.string.tile_channel_stopped_label)
                tile.subtitle = consentString(R.string.tile_channel_stopped_subtitle)
            }
        }
        tile.updateTile()
    }
}
