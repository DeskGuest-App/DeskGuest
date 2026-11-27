package io.deskguest.app

import android.app.Application

/**
 * Process entry (0.4.1): installs the crash trap before anything else
 * in the app runs, so a startup failure in any component leaves a
 * report the owner can read on the next open.
 */
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        CrashTrap.install(this)
    }
}
