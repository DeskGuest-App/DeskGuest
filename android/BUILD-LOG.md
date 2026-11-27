# Build log — DeskGuest (Android host)

## 2026-11-10 — Toolchain bring-up and the Gradle daemon problem

**Toolchain state: WORKING except Gradle.**
- Temurin JDK 21.0.12.1 (`~/workspace/tools/jdk-21`) and Temurin JDK
  17.0.21 (`~/workspace/tools/jdk-17`) both installed.
- Android SDK installed MANUALLY (see below): platform-tools (adb
  1.0.41), platforms;android-36 (android.jar verified), build-tools
  36.0.0 (aapt2 2.20 verified), licenses written with Google's
  published acceptance hashes. Root: `~/workspace/tools/android-sdk`.
- Gradle 8.14.3 distribution verified GENUINE: local zip SHA-256
  `bd711022…f3531` matches the official published checksum exactly.

**Why the SDK was installed by hand:** sdkmanager cannot download in
this VM. Its JVM HTTP stack dies in
`HttpURLConnection.doTunneling0` (NoSuchElementException) through the
egress proxy, with or without proxy -D flags. curl handles the proxy
fine, so packages were resolved from Google's official repository
manifest (repository2-3.xml) and laid down with curl + unzip.

**The Gradle problem (diagnosed, not yet root-caused):** every build
fails with "Could not receive a message from the daemon"
(DaemonConnectionException ← MessageIOException ←
IllegalArgumentException "Unexpected type tag 109"). Ruled out by
direct test:
- Not the project: an empty directory fails identically.
- Not the Gradle version: 8.13.0 and 8.14.3 fail identically.
- Not the JDK: Temurin 21.0.12.1 and 17.0.21 fail identically.
- Not a corrupt distribution: SHA-256 matches Google's published sum.
- Not a stale daemon registry: brand-new GRADLE_USER_HOME fails too.
- Not loopback TCP: cross-process Python client/server exchanges pass
  byte-identical through 127.0.0.1.
- Daemon side: starts, advertises, RECEIVES the build (state Busy);
  the daemon→client reply stream is what fails deserialization.
- Builds also fail with the whole process tree detached (setsid).
- systemd-run is unavailable from this context (no bus).

ROOT CAUSE FOUND (2026-11-10 21:45 CT, minimal Java probe): in this
sandbox, **JVM-originated loopback connects are reset**
(java.net.SocketException: Connection reset on a same-process
127.0.0.1 connect), while JVM *listening* works and native clients
(Python) connect to JVM servers byte-clean. Gradle's client is a JVM
process dialing its daemon on loopback — its connects are what die;
the daemon, the distribution, and the protocol were never at fault.
Workarounds that respect the finding: build with the manual pipeline
(no JVM-to-JVM IPC) and drive JVM-hosted test servers from Python
clients. On a normal machine (Android Studio / Jacob's laptop)
Gradle works unmodified — the Gradle project files stay in the tree
for that world.

**First compile: PASSED 2026-11-10 21:34 CT** via the manual
pipeline — `app/build/manual/DeskGuest-0.1.0.apk` (733,685
bytes), apksigner-verified. Toolchain item of S1 closed.

**S1 server core: BUILT + TESTED 2026-11-10 21:39 CT.** McpCore
(JSON-RPC: initialize / pair / tools/list / tools/call / ping),
PairingStore (one-time 6-digit codes, 10-min expiry, burn-after-use,
per-pairing bearer tokens, observe-by-default scopes, disk
persistence, one-tap revocation), McpHttpServer (fixed port 8723,
POST /mcp, GET /health, body cap, bearer auth), PhoneToolHost
(device_info, session_status), ControlService (foreground service,
persistent notification — never listens in secret). Test suites
(`test-jvm.sh`): **protocol/pairing 21/21 PASS** (pairing flow,
wrong/replay code rejection, 401s, scope gating, revocation,
persistence, error codes) and **HTTP flow 9/9 PASS** — the real
server over real sockets, driven by a Python client through the
exact agent path (health, initialize + session header, 401, pair,
tools/list, tools/call, 404). Wizard (WizardActivity: welcome,
channel, battery, notifications, connect with Tailscale detection,
report-card self-check) and home screen built the same evening.
Final APK: 762,357 bytes, signed and verified.

**DEVICE GATE PASSED 2026-11-11 07:02 CT.** Jacob installed the APK
on his Galaxy S25 Ultra, walked the wizard, and pasted the
app-written handoff prompt into chat. Muse connected from the VM
through the Tailscale CONNECT proxy to 100.72.85.56:8723: /health
200, initialize 200 (protocol 2025-03-26), pair accepted the
one-time code (token issued, observe scope), tools/list returned
device_info + session_status, and device_info read back the real
phone: samsung SM-S938U, Android 17, SDK 37, host app 0.1.0.
Two honest wrinkles: (1) the first prompt carried the phone's LAN
address because Tailscale was off — the wizard's transport
detection behaved as designed, and the fix was user-side in one
step; (2) Muse's own tunnel flapped for ~1 minute before the
connect completed (second-scale flapping, same pattern as
2026-11-10; the phone was never at fault). The S1 stage and the
morning milestone are complete; S2 (accessibility service, drive
tools, presence layer) is next.

**Update channel: INFRASTRUCTURE BUILT 2026-11-11 (Jacob approved
the BAS Hub pattern).** Plan at platform/update-channel-plan.md,
custody at platform/key-custody.md. Release key generated (RSA
4096, alias deskguest, ~/.config/deskguest/, 0600s;
cert/pubkey/key PEM exports alongside). Connector authored:
~/workspace/custom-connectors/custom.github-releases-deskguest/ (mirrors
custom.github-releases, scoped to JacobHamrac/deskguest-
releases). Publish script scripts/publish-release.py: dry run
PROVEN both ways 2026-11-11 — a debug-signed APK is REFUSED at the
signer gate; a release-signed APK produces a manifest that signs,
verifies, and refuses tampering. Remaining: Jacob creates the
public repo (owner step), token + connection registration, the live
REST sequence in the script, the in-app updater (ships in v0.3),
and the key's off-machine backup to Drive (owed, flagged).

**In-app updater core: BUILT + CROSS-PROVEN 2026-11-11.**
update/ManifestVerifier.kt + update/UpdateChecker.kt: fetch the
manifest, verify it against the app's OWN signer certificate,
compare versions, download, check SHA-256 and the APK's signer,
hand off to the installer; every failure path refuses with a plain
reason. The canonicalization rule is now pinned by a cross-test
(tests/ManifestVerifierTest.kt + make_manifest_fixture.py): a
manifest signed by the Python publisher verifies under the shipped
Kotlin code, canonical bytes identical (the first run caught a real
divergence — Python escapes non-ASCII as \uXXXX; the Kotlin writer
now matches). JVM suite: 42 checks, all pass (21 protocol, 8
snapshot, 4 manifest, 9 HTTP). UI wiring lands in v0.3.

**v0.3.0 — BUILT 2026-11-11 (Jacob approved mockup iteration 1,
07:21 CT: "use your first iteration of the mockups for the full
complete 0.3 build").** versionCode 3. Release-signed (signer
SHA-256 e738ea995efe25fe… matches the release certificate —
verified). 1,237,647 bytes.
- UI rebuilt on a shared design kit (ui/UiKit.kt: dynamic Material
  You colors with a fixed fallback palette, 24dp cards, pill
  buttons, chips, radio cards, switch rows) across a rewritten
  WizardActivity + MainActivity; plain Views, no new dependencies
  except AndroidX core classes for FileProvider (fetched from
  Google Maven into the manual pipeline).
- Wizard: BATTERY step fixed (direct intent + labelled battery-
  list fallback + honest re-check, never silent); new TRANSPORT
  step (This Wi-Fi only / Tailscale / My own tunnel — nothing
  preselected, choice persisted, CONNECT follows the choice); new
  ACCESS step after pairing ("What may <agent> do?" — Look only /
  Full control / Custom switches, consent-floor line shown);
  CHECK report includes the route + the connected agent's name.
- Server: McpCore captures MCP clientInfo at initialize and binds
  it to the pairing (the connected AI's real name now shows in the
  app and in device_info/session_status); capability gating ahead
  of scope gating (see/tap/type/apps/shell/settings), refusals name
  the missing capability; PairingStore persists agentName,
  agentVersion, access, caps (8-field TSV, legacy files load with
  observe defaults). setAccess(token, access, caps) drives the
  wizard + home editors.
- Updater wired into the home screen (UpdateChecker: check,
  download, hash + signer verify, FileProvider install hand-off).
- JVM suite: ALL PASS (McpCore 50 checks incl. 29 new, snapshot,
  manifest cross-test, HTTP flow).
- Release channel: repo JacobHamrac/deskguest-control-releases
  created by Muse through the signed-in browser (Jacob's
  direction: GitHub setup is Muse's end-to-end job); v0.3.0
  publish via the web UI with the script-signed manifest — the
  script's API live path is built but its credential is not yet
  available to the sandbox (authd policy), so the token route
  remains to be exercised. **Publish VERIFIED 2026-11-11 07:35 CT:**
  the app's exact manifest URL serves the signed manifest — every
  field compared against the locally signed file (version, code,
  full APK SHA-256 3190ceb5…, size 1,237,647, URL, publishedAt,
  signature) matches; the local manifest's signature verifies.
  (Direct curl from this VM was proxy-aborted twice; the comparison
  ran on the page-fetch copy of the live file.) First live publish
  through the channel: DONE.
- Install note: 0.3.0 is the key switch — uninstall 0.1/0.2 first;
  pairings do not carry over.

**S2 core: BUILT 2026-11-11 07:06 CT (v0.2.0, versionCode 2).**
ControlAccessibilityService (window-tree snapshots with refs,
screenshot via the service API, gesture dispatch, text entry,
global back/home/recents), AccessToolHost (current_app, snapshot,
screenshot as MCP image content, start/end_session, tap by ref with
live re-validation, tap_point, swipe, type_text, press — all
drive-gated behind an open session and honest-unavailable when the
service is unbound), PresenceOverlay (edge glow + "…is controlling
your phone" banner + a separate touchable STOP window that ends the
session on-device), SessionManager, and wizard steps 5–6
(accessibility via the Restricted Settings path, overlay) with
report-card rows for both. McpCore gained rich content support
(runContent). Suites: 38 PASS (21 protocol + 8 snapshot-ref
discipline + 9 HTTP). NOT yet device-proven: the accessibility
grant and overlay grant are Jacob's taps; the S2 device gate is a
live session on the S25 ending in a snapshot/screenshot read-back
and an on-screen STOP test.

**Decision:** build with the manual pipeline (`build-manual.sh`):
aapt2 → kotlinc → d8 → zipalign → apksigner. Plain CLI processes, no
daemon, no IPC protocol. The scaffold app was switched from Compose
to plain Views for the pipeline bring-up; UI toolkit choice for the
wizard is revisited once the pipeline is proven (Material Components
AARs can be linked manually; Compose remains possible via manual AAR
resolution if wanted).

**Environment gotchas banked:**
- /tmp is a 512 MB tmpfs — large downloads must land on the home disk.
- The egress proxy answers Google/Maven hosts WITHOUT authentication
  from this VM (verified 200s); gradle.properties carries host/port
  systemProps only, never credentials.
- `pkill -f <pattern>` can match the caller's own shell command line;
  kill by PID.

### v0.3.1 (2026-11-11) — banner names the connected agent
Jacob's S2 gate catch: the live banner read "My AI is controlling your phone" — the pairing's display name — although the whole point of the clientInfo work was that the banner names the connected AI. Root cause: AccessToolHost.start_session called SessionManager.start("My AI") with a hardcoded literal; the S2-era ToolDef run lambdas receive no caller (no ToolHost→core back-reference existed). Fix: McpCore.Caller + ThreadLocal currentCaller set per tools/call from the authorized pairing; ToolHost.attach(core) added (CompositeToolHost forwards; AccessToolHost stores the core) so start_session opens the session under Caller.displayName (agentName, pairing-name fallback). JVM suites green; APK 1,237,647 bytes, versionCode 4. STOP verified live by Jacob on 0.3.0 before this fix; the banner-name re-proof rides the 0.3.1 update.

### v0.3.2 (2026-11-11) — virtual finger + banner pill
Jacob's second and third catches from the S2 gate, back to back:
(2) "No finger pointer" — honest: the virtual finger was specced (SPEC §7.3, FEATURES V1) and shown in the mockups, but the S2 presence build shipped glow + banner + STOP only; the finger was never implemented, and the 07:47 live test made that visible. Built now: fingertip dot (halo + white ring + violet core, drawn in code, no assets) in its own touch-through overlay window; glideTo animates it (450ms, decelerate) to the target BEFORE the gesture dispatches (tap/tap_point sleep 680ms — glide + beat; swipe glides to start, then to end); rippleAt expands a fading ring at the tap point and the finger parks dimmed (alpha .55) at the right edge. tap-by-ref needed a target: ControlAccessibilityService.refCenter(ref, snapshotId) exposes the resolved centre. Note: nodes tapped via ACTION_CLICK show finger + ripple at the element centre but the click itself is still instant once the beat ends (gesture taps animate fully).
(3) Banner "looks like a line of text / early 2000s" — restyled to the mockup: floating pill (56dp corners, near-opaque dark, hairline light border, elevation shadow, violet status dot, more padding); STOP is now a matching pill (bold, elevation, no state-animator shading) moved below the banner (y 132 vs 36) so it no longer overlaps the clock/weather. versionCode 5, APK 1,241,743 bytes. Supersedes 0.3.1 (which was published minutes earlier with only the banner-name fix; 0.3.2 includes it).

### v0.3.3 (2026-11-11) — presence watcher lifecycle fix
Jacob's fourth catch, the serious one: during the 0.3.2 finger demo the session was live (his Settings opened) but NO indicators were on his screen — "You opened the settings then you disappeared"; the screenshot Muse took mid-session confirms it (Settings UI, no glow/banner/STOP/finger; Muse even attached it as success evidence without seeing the absence — an inspection failure, banked below). Root cause: the 0.3.0→0.3.2 update restarted ControlService; the NEW instance's onStartCommand only starts its server thread `if (httpServer == null)`, but the static field still referenced the dead pre-update instance, so start() (which carried the ONLY PresenceOverlay.watch call, in a finally block) never ran. The MCP server kept answering because McpHttpServer.start() spawns a non-daemon thread that outlives its Service — control channel and presence decoupled, exactly the failure the product's consent design forbids. Fix: watch() moved to onCreate (service lifecycle == watcher lifecycle). Deeper structural risk REMAINS, named honestly: the server thread outliving its service is itself wrong (S4/S5 work: bind server lifetime to the service; session-persistence across service restarts needs a deliberate design, not an accident). versionCode 6, APK 1,241,743 bytes (dex-identical size to 0.3.2 — the moved call is the only change).
Banked method fix (extends the shipped-artifact rule): a session screenshot is EVIDENCE ABOUT PRESENCE, not just about the target app — before claiming any drive success, read the screenshot for the presence elements themselves; their absence fails the test no matter what the tool results say.

### v0.3.4 (2026-11-11) — a real finger pointer
Jacob's fifth catch: the 0.3.2 "finger" rendered as a small purple dot; his design intent all along was "an actual finger pointer". Rebuilt FingerDrawable as a pointing-hand cursor in the system-pointer tradition (paths drawn in code — per the real-assets rule this is a UI cursor glyph, not a brand mark): white fill, dark outline, soft shadow, 120x152 window, fingertip anchored at (38,6) of a 100x126 design space with a small violet dot marking the exact touch point. Glide slowed 450→800ms and the pre-tap beat raised so the travel + hover reads (sleep 680→1050ms; swipe 500→800ms). Includes the 0.3.3 watcher-lifecycle fix (0.3.3 published 08:06; superseded before Jacob installed it). versionCode 7. Open craft risk, stated plainly: the hand path is hand-tuned coordinates drawn blind — Jacob's eyes on the real device are the verdict; if the silhouette reads wrong it gets redrawn from his screenshot.

### v0.3.4 live test — presence STILL absent (2026-11-11 08:12)
Ran the full gate sequence on 0.3.4 (start → home → tap Settings → screenshot DURING the session → read the screenshot for presence FIRST): the screenshot again shows plain Settings — no banner, no glow, no STOP, no finger. The 0.3.3 watcher fix did NOT restore presence on the real update path. Verified from the outside that the server IS the freshly restarted process (uptime 27s), so onCreate ran — with the watch call in it — and presence still never appeared. Surviving hypotheses: (H1) Settings.canDrawOverlays returns false post-update (grant tied to the old install — considered unlikely: grants key on package+uid, uid is stable across same-signer updates); (H2) an exception inside the watcher/show path is swallowed (watch posts a Runnable; show() has no try/catch around addView of the frame itself beyond attachment; a throw in the poll runnable would kill the loop silently — Handler runnables that throw crash... on the main looper an uncaught exception crashes the process; the process lived, so a repeated throw is unlikely, but a throw inside post() scheduling is not excluded); (H3) appContext race — watch() stores applicationContext then posts; show() uses it — should be fine; (H4) the overlay permission was revoked/reset by the 0.3.0 uninstall (the KEY-SWITCH reinstall!): the overlay grant was given to the DEBUG-signed install, and the release-signed reinstall is a NEW app install as far as app-ops are concerned... but Jacob re-granted overlay during the 0.3.0 wizard (step 9) — unless the wizard's detection read a stale state. Device-side diagnosis needed: dumpsys window (are the overlay windows attached?), appops SYSTEM_ALERT_WINDOW for the package, and the presence state the app itself reports. The honest blocker: Muse's two phone lanes are both down for shell access (ADB lane port undiscovered since 2026-11-10; DeskGuest has no shell tool at observe/full caps as built — shell is a capability in the access model but no shell TOOL exists yet). Next diagnostic step: the app should report its own presence state — add a presence self-report to device_info (overlay grant state, watcher running, attached state) in 0.3.5 so this class of failure is diagnosable through the MCP channel itself, plus log the show() path's failures instead of swallowing them. Until then: DO NOT claim presence works; the gate stays open and red.

### v0.3.5 (2026-11-11) — presence becomes a guarantee
Jacob's field diagnosis (08:13) cracked what two of Muse's hypotheses couldn't: the indicators drop out WHILE SETTINGS IS IN FRONT and return when he leaves it — presence was rendering (proven on the launcher in the 07:45 shot), so the watcher-lifecycle theory was wrong; the windows were being dropped/hidden over that surface. His rule, stated plainly and adopted as product law: "the indicators should never disappear as long as you are controlling, otherwise a user will not know if they are allowed to take back over."
Rebuild, three mechanisms so no single failure can take presence down: (1) EVENT-DRIVEN — SessionManager gained listeners; start/end notify synchronously, PresenceOverlay renders on the session event itself (the 600ms→5s poll is demoted to backstop); (2) LAYER — all four windows (frame, STOP, finger, ripple) use TYPE_ACCESSIBILITY_OVERLAY when the accessibility service is bound (sessions require it anyway), falling back to TYPE_APPLICATION_OVERLAY otherwise; (3) WATCHDOG — the backstop poll verifies rootView.isAttachedToWindow during live sessions and re-shows when detached. Plus device_info now carries a presence self-report (overlayGranted, watcherRunning, bannerAttached, sessionActive, windowLayer) so the next presence question is answered by the app, not by theory. versionCode 8, APK 1,245,839 bytes. The gate re-test is now PRECISE: screenshot taken while Settings is in front, mid-session, must show banner+glow+STOP; diagnostics read before and after.

### v0.3.5 gate test — presence STILL absent; self-report caught it; root cause narrowed (2026-11-11 08:19–08:23)
- Self-update driven entirely by Muse (Jacob's 08:18 realization: "you can drive and do it all yourself"): session → app drawer → DeskGuest → Check for updates → Download and install → chooser (Package installer) → installer sheet. Two 60ms tap_point presses at the Update button (1015,2965 then 1015,2870) did NOT register (sheet unmoved); a 300ms swipe-press at the tree-reported Cancel anchor (1015,2891; the sheet renders ~100px lower than the accessibility tree reports — buttons sit at the very bottom edge, partially below the tree's frame) DID land. Install verified: device_info flipped to 0.3.5 on the first poll. NEW TOOL FACT: tapAt dispatches a 60ms stroke, which system sheets can treat as a non-press; press-and-hold class targets need a longer stroke (the swipe tool at 300ms is the working workaround until a press tool exists).
- GATE TEST on 0.3.5 (start → home → tap Settings → screenshot with Settings in front): presence STILL ABSENT in the screenshot, AND the new self-report says bannerAttached=false at every in-session read while sessionActive=true, watcherRunning=true, overlayGranted=true, windowLayer="accessibility". So show() either never runs or its addView throws and the catch swallows it. Eliminative record: the windows ARE in the accessibility screenshot layer (07:45 evidence: banner + STOP pixels present in an accessibility takeScreenshot) — the "capture blind to app overlays" theory is DEAD. Hypotheses eliminated across 0.3.2–0.3.5: watcher lifecycle (0.3.3), poll death (event-driven 0.3.5), overlay grant (self-report: granted), layer choice (accessibility layer reported). Surviving: (a) SessionManager listener never registered in the live process or its posted show() dying silently — note ControlService.onCreate calls watch() TWICE (applicationContext at line 30, `this` at line 48) and the `watching` guard makes the second a no-op (harmless); (b) addView throwing with the exception swallowed by the bare catch; (c) appContext null at show() time. 0.3.6 MUST instrument, not theorize: record lastShowAttempt/lastShowError/lastShowAt + stopAttached + fingerAttached into diagnostics, log the throwable, and self-heal (watchdog retries show() when sessionActive && !bannerAttached). No further presence claims until diagnostics show bannerAttached=true AND a Settings-front screenshot shows the elements AND Jacob sees them.

### ROOT CAUSE FOUND + v0.3.7 built; Jacob paused the work (2026-11-11 08:30–08:32)
- 0.3.6 self-update: the 1px-offset 300ms press FAILED again; a ZERO-LENGTH 300ms press (same start/end point — a true press-and-hold, no drag vector) at (1015,2891) LANDED. Rule: installer-sheet presses are zero-length 300ms swipes at the tree-reported anchor. (Direction of causality for the earlier confusion: the 08:21 "success" was likely the second tap_point landing during the sheet's settle, not the anchor theory — the zero-length press is the proven mechanism, twice is not needed: it worked first try.)
- 0.3.6 GATE DIAGNOSTICS — the instrumentation paid off in one read: listenerCalls=1 (listener fires), showAttempts climbing 3→7 (listener + watchdog retries all running), lastShowError = "addView(frame): BadTokenException: Unable to add window -- token null is not valid; is your activity running?" ROOT CAUSE: TYPE_ACCESSIBILITY_OVERLAY windows must be added through the AccessibilityService's own context — the window token belongs to the service; adding them from the application context is rejected every time. The 0.3.5 layer change created this failure while chasing the wrong theory; in 0.3.4 (app-overlay type) show() presumably succeeded and the windows vanished by a different mechanism — BUT note the 07:45 0.3.0-era banner proves app-context adds of TYPE_APPLICATION_OVERLAY work, so the pre-0.3.5 disappearance remains its own open question; the watchdog + self-report now stand guard over whichever mechanism applies.
- v0.3.7 FIX (built, suites pass, NOT published — Jacob paused): all presence windows (frame/STOP/finger/ripple) are created from windowContext() = ControlAccessibilityService.instance when bound (the service's context + its WindowManager), falling back to the app context otherwise. versionCode 10. APK app/build/manual/DeskGuest-0.3.7.apk.
- PAUSE STATE (Jacob, 08:32, at work): gate session ended by Muse; phone left on 0.3.6, no session open. To resume: stage 0.3.7 via publish script → publish via browser → Muse self-drives update (zero-length press rule) → gate test (diagnostics bannerAttached=true + Settings-front screenshot + Jacob's eyes).

### v0.3.7 resume — published; installer-press "rule" CORRECTED (2026-11-12)
Jacob lifted the pause 16:54 CT. Staged via the publish script (signer gate passed; manifest signature verified): APK sha256 ed70f76a752e…, 1,245,839 bytes, versionCode 10. Published via the signed-in browser (16:55–16:56 CT): release v0.3.7, Latest, both assets; the live manifest was fetched and compared field-for-field against the signed local file (versionName, versionCode, publishedAt, signature head/tail/length, APK sha256 + size) — MATCHES. Phone channel probed live on the first attempt: 0.3.6 server answering, presence self-report nominal for no-session. Self-drive: drawer search → DeskGuest → Check for updates → "Version 0.3.7 is ready (1.2 MB)" with correct notes → Download and install → "Open with" chooser → Package installer → installer sheet.
- CORRECTION (supersedes the 0.3.6 entry's "rule"): the zero-length 300 ms press is NOT a reliable mechanism. Today the sheet ignored FIVE attempts at the visually confirmed Update position (own screenshot read: Update centre ≈ (1037,2880); tree Cancel anchor (418,2891) agrees): zero-length 300 ms ×3, tap_point 60 ms ×1, micro-drag ×1 — with 14 device_info polls showing the version never moved off 0.3.6. The 0.3.5/0.3.6 landings are reclassified as unmechanistic luck (sheet-settle timing), not a technique. Standing fact: installer-sheet confirmation from accessibility gestures is UNRELIABLE; the dependable path is the user's own tap on Update, or a future multi-stroke press-and-hold tool. Jacob was asked for the one tap at 17:02 CT.
- Process correction banked (again): Muse initially tracked version polls instead of looking at the phone's screen; the screenshot tool was on the channel the whole time. Jacob: "Don't you see that yourself?" Look first; polls are corroboration, not eyes.
- Gate test pending: on Jacob's Update tap → verify version flip → gate sequence (diagnostics bannerAttached=true + Settings-front screenshot read for presence + Jacob's eyes).
- PLAY PROTECT BLOCK (2026-11-12 17:04 CT): Jacob tapped Update himself; the install began ("Updating…" visible) and Google Play Protect intervened with "Harmful app blocked — DeskGuest — This app can put your device or data at risk." The update did NOT land: device_info still reports 0.3.6 and the app still answers (session alive, showAttempts 199 — the 0.3.6 presence bug still cycling). Yesterday's 0.3.4→0.3.5→0.3.6 updates installed through the same path unblocked; the verdict changed since. This is SPEC §12's known unknown ("Play Protect behaviour with sideloaded accessibility+ADB apps") arriving on schedule: an accessibility-service app, sideloaded, self-updating — the exact profile Play Protect escalates on. Product consequence: direct distribution must design for this (wizard teaches a Play Protect pause during setup, or the app gets classified and blocked for ordinary users too) — S4/S5 design input, not yet solved. Immediate state: phone healthy on 0.3.6; gate test cannot run until 0.3.7 lands; landing it needs Jacob's decision on pausing Play Protect scanning (Play Store → profile → Play Protect → gear → "Scan apps with Play Protect" off), then re-drive + his Update tap.
- CORRECTION to the Play Protect entry above (Jacob, 17:06 CT): the block dialog has appeared on EVERY install in this process (0.3.5, 0.3.6, 0.3.7) — Jacob tapped through it each time via More details → "Install anyway" without mentioning it. So: no cloud-verdict change, no new escalation; Play Protect interrupts every install of this app and a human "Install anyway" tap is the standing gate. That also re-shades yesterday's install history: the version flips rode on Jacob's Install-anyway taps, not on the sheet presses alone. Standing update flow, corrected: Muse drives to the installer sheet → Jacob taps Update → Play Protect interrupts → Jacob taps More details → Install anyway → install completes → Muse verifies. Two human-reserved taps per update on this phone. Product consequence stands (the wizard/setup must expect and teach this dialog for every user), but no Play Protect pause is needed — the per-install override suffices and the scanner stays on.
- GATE TEST on 0.3.7 (2026-11-12 ~17:07 CT): Jacob tapped Install anyway; version flipped to 0.3.7 on the first poll. Gate sequence run in one session: start_session → diagnostics read bannerAttached=true, stopAttached=true, showAttempts=1, listenerCalls=1, NO lastShowError (0.3.6's last comparable read: showAttempts 199, attached false, BadToken on every attempt) → press home → opened Settings (com.android.settings verified in front) → diagnostics STILL bannerAttached=true / stopAttached=true with Settings in front → screenshot read FOR PRESENCE before any claim: violet edge glow on all four sides, banner pill "Muse is controlling your phone" with status dot, red STOP pill, pointing-hand finger parked at the right edge — ALL FOUR ELEMENTS PRESENT over the exact surface that killed them in 0.3.2–0.3.6. Screenshot: ~/workspace/phone-captures/deskguest-0.3.7-gate-settings.png. The windowContext fix is PROVEN on device: presence now attaches on the first attempt, through the accessibility service's own context, and holds over Settings. Leg 3 (Jacob's eyes + his own STOP tap) requested in the delivery message; session left open for it.
- GATE CLOSED (2026-11-12 17:08 CT): Jacob tapped STOP on the phone himself — presence disappeared; app records confirm sessionActive=false, bannerAttached=false, stopAttached=false, listenerCalls=2 (start + end both rendered), showAttempts stayed 1. All three gate legs pass: (1) diagnostics attached first try and held over Settings; (2) screenshot shows glow + banner + STOP + finger over Settings; (3) Jacob's eyes + his own STOP tap, which also proves the user override end-to-end. The S2 presence gate — open since 2026-11-11 07:47 and red through five builds (0.3.2–0.3.6) — is CLOSED by 0.3.7. Remaining stages: S3 self-ADB (client audit done 2026-11-11), S4 policy gates/audit/replay + bind server lifetime to the service, S5 hardening (PairingStore Keystore wrap, press-and-hold tool, wizard teaches the Play Protect Install-anyway step). Release-key Drive backup still owed.
- DESIGN INPUT (Jacob, 2026-11-12 17:09 CT): "when the user's AI completes their task they should automate ending the session — that way the user knows they are done." Written into SPEC §7.8a + FEATURES (V1): agent ends the session as its final action (handoff prompt carries the instruction; leaving one open is a protocol violation), app backstops (session closes on agent disconnect; idle timeout last resort), session end announced (sound/haptic + closing log entry). App-side enforcement lands with S4's session-lifecycle work; the norm binds Muse's own driving from today — the gate session was left open deliberately for Jacob's STOP test, ordinary tasks get ended by the agent.

- PRESENCE LEAK — NEW 0.3.7 DEFECT (2026-11-12 18:39–18:47 CT, Jacob's catch #9): after the vault-cleanup session ended (end_session reported closed; session_status sessionActive=false), the glow + banner + STOP remained PAINTED on the phone. The presence self-report claimed bannerAttached=false / stopAttached=false while a no-session screenshot (~/workspace/phone-captures/vault-clean-stuck-check.png) showed all elements on screen — the self-report tracks bookkeeping, not the WindowManager, and cannot be trusted as proof of presence state in EITHER direction (mirror image of catch #4). Jacob's STOP taps did nothing: the leaked windows are not the tracked instances STOP/hide() reach. A session open/close cycle was never given the chance to help (the lying report suppressed it) and by design hide() removes only tracked views. Cleared by force-stopping the app from Settings (drove: Settings search → App info → Force stop → OK; channel death confirmed the process died; windows cannot outlive their process). Channel stays down until Jacob relaunches the app once; pairing/settings persist. FIX OWED in the next build (S5 list): show() must be idempotent (one window instance per element, tracked in a single registry), hide() must sweep every window the overlay ever added, the watchdog must reconcile against actual attachment during AND after sessions, and the presence self-report must be derived from real attachment state. Verification rule re-banked: presence claims are proven from a SCREENSHOT, never from the self-report alone — in both directions.

### v0.3.8 (2026-11-15) — presence redesign + customizable presence colors; pairing fix folded in
Version state reconciled before the bump: source stood at 0.3.7 (versionCode 10, published) with the DeskGuest Android pairing-blocker fix already in source but unstaged and unpublished (PairingStore: a pairing code is burned after MAX_REDEEM_ATTEMPTS = 5 wrong guesses; wrong guesses before the limit do not burn it). This release folds that fix in — it ships here for the first time. versionCode 11.
- DESIGN SOURCE: Jacob fed the live presence screenshot (~/workspace/phone-captures/deskguest-presence-live.png) to Gemini and approved its restyle (thicker bright violet glow with soft bloom, glowing arrow cursor with ripple, target highlight, integrated banner). Built to that design with Jacob's two corrections on top: consent wording does NOT soften (banner still reads "<agent> is controlling your phone", not Gemini's "managing your device") and STOP does NOT shrink (same size, position, and padding as 0.3.7; only its color became customizable).
- GLOW: the 10px GradientDrawable stroke is replaced by GlowView, a custom view painting two strokes of one rounded rect in the glow color — a 46px blurred bloom (BlurMaskFilter, software layer) under a 15px bright core at alpha 235, corner radius 52px. The bloom breathes on a slow 2.6s reverse animator (alpha 64↔112) while a session is live; the core is steady. Pulse stops in hide().
- CURSOR: the pointing hand (0.3.4) is replaced by an arrow cursor drawn in code in the cursor color — filled path with a same-color shadow bloom, a thin light edge for bright screens, and a white dot at the tip marking the exact touch point. Same window size (120x152), same tip anchor (38,6 of the 100x126 design space), same 800ms glide and park-dimmed behaviour.
- RIPPLE: RippleDrawable now takes the ripple color and adds a soft filled disc under the expanding ring (ring stroke widened 5→7px, same-color shadow).
- TARGET HIGHLIGHT (new): PresenceOverlay.highlightBounds(l,t,r,b) paints a translucent wash (fill alpha 46 + stroke alpha 175, 22px corners, 12px pad) over the element about to be tapped, in its own touch-through window reusing one tracked view. Wired into the tap tool (bounds from the new ControlAccessibilityService.refBounds, shown before the glide, cleared 550ms after the tap lands via scheduleClearHighlight) and tap_point (a 140px box at the point). Cleared in hide().
- BANNER: text and pill unchanged; the status dot takes the banner-accent color and the pill's hairline border is now the accent at alpha 120 instead of plain white.
- COLOR CUSTOMIZATION (Jacob's requirement, this build): new presence/PresencePalette.kt (pure logic: six items — glow, cursor, ripple, highlight, banner accent, STOP — defaults in the violet family with STOP red #C62828; 12 preset swatches; #RRGGBB parse/format; Config get/with) and presence/PresenceSettings.kt (SharedPreferences file "presence", one hex string per item; missing/unreadable values fall back to defaults). MainActivity gains a Presence section (UiKit patterns): one row per item with a color swatch + current hex; tapping a row expands its editor (preset swatches, hex field with Apply, invalid hex refused with a plain toast); Reset colors to defaults at the foot of the card. Every change saves at once and calls PresenceOverlay.refreshColors(), which reloads the palette and — if a session is open — re-renders presence (hide + show) so the new colors apply live; otherwise the next session picks them up. PresenceOverlay.watch() also loads the saved palette at channel start.
- COMPILE CATCH (banked): inside GradientDrawable.apply blocks, the unqualified name `colors` resolves to GradientDrawable's own getColors()/setColors() property (IntArray), not the overlay's field — three unresolved-reference errors (bannerAccent, stop) while identical uses outside those blocks compiled. Fixed by renaming the overlay's field to `palette`. Rule: never name a field `colors` in code that builds GradientDrawables.
- JVM SUITES: ALL PASS, 107 checks, 0 failures — McpCore 59, SnapshotStore 8, PresencePalette 27 (new suite: defaults, hex accept/refuse forms, round-trips, Config get/with, alpha clamp), ManifestVerifier 4, HTTP flow 9.
- APK: DeskGuest-0.3.8.apk, 1,254,031 bytes, SHA-256 8d101edaeae8e0b0…; apksigner verifies; signer SHA-256 e738ea995efe25fe… matches the release certificate (same key as every 0.3.x release). Staged at ~/workspace/agent-control-app/release-staging-0.3.8/ (APK + signed update-manifest.json; the staged manifest's signature verifies; its publishedAt is the staging time — a live publish rebuilds it) and copied to ~/workspace/your_files/DeskGuest-0.3.8.apk. Publish dry run PASSED all gates (badging, signer, signature, tamper refusal).
- PUBLISH STATE: NOT PUBLISHED. The single live attempt in the build run was refused before any API call: the publish script could not attach the credential from the registered connection (github-releases-deskguest) — authd returned HTTP 403, "this connector's credentials are not available to the sandbox" (the same standing blocker recorded at 0.3.0; 0.3.7 was published through the signed-in browser instead). To publish: run the script's --live path from a context that can attach that credential, or publish via the signed-in browser exactly as 0.3.7 (create release v0.3.8, upload the staged APK + update-manifest.json, then fetch the live manifest from the app's URL and compare field-for-field).
- UNPROVEN (device gate, Jacob's install step): nothing in this build has run on the phone. After Jacob installs 0.3.8 (the usual two human taps: Update, then Play Protect More details → Install anyway), the presence gate must be re-run for the new design: diagnostics attached + a Settings-front screenshot read FOR PRESENCE (glow bloom, banner, STOP, arrow cursor, and a tap showing highlight + ripple) + Jacob's own STOP tap. The 0.3.7 presence-leak fix (idempotent show / hide sweep) remains owed and is NOT in this build.

### v0.4.0 (2026-11-15) — the full build, one version
Jacob's direction (21:05, amended 21:06): build EVERYTHING from PLAN-0.4.md (Gemini design + backend review, reconciled) and bake it into ONE version — internal stage order and test gates kept, single artifact shipped. versionCode 12.
- STAGE 1 (look + hardening): Daylight-White restyle of the whole app per the approved Gemini design set (Home idle/active, wizard 3a–3c, Presence, Update, overlay); presence defaults flip to light blue #38BDF8 (stored user colors kept; STOP stays red); pointing-hand cursor replaces the 0.3.8 arrow; intent narration line; server binds tailnet+loopback only (was 0.0.0.0) with Origin rejection + Host validation; constant-time token compare; Keystore AES-GCM token wrap; pairing lock + 500ms backoff; password fields redacted in snapshots and refused by type_text; snapshot BFS caps (1500 nodes / 35 depth) with a loud truncation flag; generation-counter presence lifecycle + watchdog reconcile against real attachment (the owed 0.3.7 leak fix); touch-to-yield PAUSED_BY_USER (Resume forces a fresh snapshot; paused calls fail with a structured PAUSED error); binding watchdog (ENABLED vs BOUND → BINDING_STALE) with the wizard's toggle-cycle walkthrough; QS TileService; manifest monotonic-versionCode enforcement in the update checker.
- STAGE 2 (gates + audit + tools): per-class approval gates (Auto / Ask First / Blocked) with an on-phone Approve/Deny overlay, 30s timeout = deny; gates ship WITH the tools they govern: launch_app, wait_for (event-driven), annotated_screenshot, clipboard_set, clipboard_get (foreground-only — Android blocks background reads; clipboard wiped at session end); encrypted append-only audit log (JSONL, secrets redacted pre-write, export-only from the app, NO MCP read path).
- STAGE 3 (shell channel): self-paired wireless-ADB channel implemented in-app — mDNS discovery, SPAKE2 + AES-GCM pairing, RSA identity, shell_exec, settings_get/put with mandatory read-back verification, package_info; Drive+Shell scope gated. Protocol math validated against published AOSP/BoringSSL references, never app-against-itself. On-device pairing proof is a Jacob-gate item (needs his pairing code from Developer options).
- STAGE 4 (mesh client): Windows device page per the approved design (live-preview slot, companion state, trackpad + modifier drive, Hand Off, Disconnect). Honestly reports "companion offline" until the Windows companion (PLAN-WINDOWS W1, in build the same night) exists — no fake preview.
- JVM SUITES: ALL PASS — 249 checks, 0 failures (McpCore, Snapshot, PresencePalette, Session, PairingStore, Stage-2, AdbCrypto, Mesh, Manifest, HTTP), verified by the parent directly after the build run ended without its final report: the parent re-ran the full suite twice, re-ran the publish dry-run gates, staged the release, and verified every artifact itself before publishing.
- APK: DeskGuest-0.4.0.apk, 1,331,925 bytes, SHA-256 4f71db0fdf20de9c…; signer verified (release cert, same key as all 0.3.x). Staged at ~/workspace/agent-control-app/release-staging-0.4.0/ (APK + signed update-manifest.json; manifest signature verifies, tamper refused) and copied to ~/workspace/your_files/.
- PUBLISHED 2026-11-15 22:02 CT via the signed-in browser (script route still blocked on the sandbox credential, standing since 0.3.0): https://github.com/JacobHamrac/deskguest-control-releases/releases/tag/v0.4.0 — Latest, both assets listed; GitHub's server-side digest of the live manifest (ee52b31161ef…) matches the signed local file exactly — byte-identical. (A direct fetch of the manifest URL from this VM timed out on the proxy; the digest comparison is the verification of record.)
- UNPROVEN (device gate, Jacob's install): nothing in this build has run on the phone yet. Gate after install: presence in the new design (light-blue glow, banner, STOP, hand cursor, highlight+ripple) proven from a Settings-front screenshot; touch-to-yield pause + Resume; zero presence windows after session end (in-app tracked-window self-check + screenshot); approval prompt round-trip; shell-channel pairing with Jacob's code; Windows page shows companion-offline honestly. 0.3.8 was never installed and is superseded — Jacob updates 0.3.7 → 0.4.0 directly.

### v0.4.0 INCIDENT — startup crash on upgraded installs (2026-11-15 22:04 CT, Jacob's catch)
Jacob updated 0.3.7 → 0.4.0 and the app crashed instantly on open; the control channel was down (connection refused on 8723 — process dead). Root-cause record, from the parent's own inspection:
- The shipped APK was built at 21:52 from a source snapshot taken mid-program: sources.txt (regenerated by the build itself) lists 47 files; WindowsDeviceActivity.kt and the mesh classes were written at 21:53, AFTER the build, and MainActivity.kt was edited at 21:53 too. The APK's manifest (compiled from the newer tree) declares .WindowsDeviceActivity, which the dex does not contain. The build coordinator ended without a final report; the parent verified tests/APK/publish gates but did NOT verify that the shipped dex matched the finished source — the exact shipped-artifact gap the second-inspector rule exists to close. That miss is the parent's.
- The precise throwing frame was never captured (no shell lane to the phone; the app had no crash reporting) — which is itself the second defect 0.4.1 closes. The stale-snapshot build is the proven defect of record; whether the crash was the snapshot's inconsistency or a runtime fault in the staged code, the corrective build supersedes both.
- Process fixes banked: (1) scripts/check-dex.py — a build gate that parses classes.dex class_defs and fails the build unless every manifest component is DEFINED in the dex; run against the shipped 0.4.0 APK it fails and names WindowsDeviceActivity. build-manual.sh now runs it as step [7/7]. (2) The manual build never packaged assets (no -A flag) — the bundled fonts silently fell back in 0.4.0; fixed in the pipeline. (3) The app now records its own crashes (CrashTrap) and shows the report on next open.

### v0.4.1 (2026-11-15) — clean rebuild + crash reporting + startup hardening
versionCode 13. Clean rebuild from the COMPLETE source tree (all four stages, incl. the Windows device page and mesh classes the 0.4.0 package lacked).
- CrashTrap (new, app/CrashTrap.kt + app/App.kt Application class, manifest android:name=".App"): uncaught exceptions are written (timestamp, thread, full stack) to files/last-crash.txt before the system handler runs; MainActivity shows the report FIRST on the next open, with "Clear report and open the app". Startup code also records caught failures there.
- Startup hardening: ControlService builds each tool host (Phone/Access/Shell) under its own Throwable guard — a failing host degrades the channel and is recorded instead of killing the process; PresenceOverlay.watch, McpHttpServer.start, at-rest cipher and audit-store init likewise guarded (catches widened from Exception to Throwable, because NoClassDefFoundError is an Error). MainActivity renders every home-screen section under a per-section guard that records the failure and substitutes a note.
- Build pipeline: aapt2 link now packages app/src/main/assets (Inter + JetBrains Mono ship for real); step [7/7] runs the dex completeness gate — PASSED (2,296 classes; every manifest component defined).
- JVM SUITES: ALL PASS, 249 checks, 0 failures (re-run by the parent on the final tree).
- APK: DeskGuest-0.4.1.apk, 1,897,383 bytes, SHA-256 61b99e391553c6e9…; signer verified (release cert). Staged at release-staging-0.4.1/ (signed manifest verifies; tamper refused) and copied to ~/workspace/your_files/.
- PUBLISHED 2026-11-15 22:15 CT via the signed-in browser: https://github.com/JacobHamrac/deskguest-control-releases/releases/tag/v0.4.1 — Latest; GitHub's digests for both live assets match the local files exactly (manifest 057e476d…, APK 61b99e39…).
- RECOVERY PATH for Jacob (0.4.0 cannot open its own updater): install the 0.4.1 APK directly from the release page in the phone browser — same signer, higher versionCode, installs over the top, pairings/settings preserved; then the standing two taps (Install, Play Protect Install anyway).
- UNPROVEN until Jacob installs: that 0.4.1 opens clean on his phone with his 0.3.7-era data. If anything still fails at startup, the app itself will now show the stack — that screenshot is the next diagnostic input. The full 0.4.x device gate (presence, touch-to-yield, zero-window, approvals, shell pairing) remains owed after the app opens.

### v0.4.7 — Block D stream viewer (recovery lane notes, 2026-11-20)
- StreamViewer.kt (the dead lane's Android half of Block D) compiles
  into the build: `./build-manual.sh` OK — DeskGuest-0.4.7.apk,
  2,057,206 bytes, SHA-256 d47e487982126f675aae611147bcb73f006c1a7449a628484a641f232a287646,
  2,492 classes in dex (0.4.6 baseline 2,426); StreamViewer /
  MeshProtocol / StreamFrames classes present in dex.
- JVM suites: `./test-jvm.sh` reported 1153 PASS / 1 FAIL and aborted
  at TransportTest per `set -e`. The one failure is
  `DESTRUCTION unauthenticated LAN attempt is refused and dropped`
  in TransportTest — the sibling transport lane's scope; observed by
  this lane, NOT fixed here, flagged for the transport lane.
  Stream-relevant suites run standalone from the compiled classes:
  MeshProtocolTest 28/28 PASS (13 stream-specific checks),
  ManifestVerifier all-pass, HTTP flow 5/5 PASS.
- STAGING: the held staging of record for 0.4.7 is the sibling lane's
  later build at `release-staging-0.4.7/` (APK SHA-256
  c3bb8e7cefc832301a98b7770d15ff4932b071e061eb693d74c66d79632dee8e,
  verified on disk by this lane; manifest signed/verified per the
  sibling's RUN-REPORT entry) — STAGED-HELD, NOT published. This lane
  created no competing staging. Phone untouched; on-device stream
  behaviour unproven (and the Windows-side encoder is blocked on the
  laptop's Media Foundation build — see windows-agent RUN-REPORT.md,
  Block D).
