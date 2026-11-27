package io.deskguest.app.rmm
import java.security.MessageDigest
/** Lane B2: RMM-01/02/04/17/18/19/25/27/32 Android mirrors. Pure model layer
 * (Enterprise.kt precedent). Honesty rules are types, not comments:
 * unreadable sections are absent+named; impossible capabilities have no API. */
object RmmToggles { // TOTAL POLICY CONTROL: every feature toggleable, default per item
  // bd-and-rmm F2 fix (2026-11-22): keys aligned to the RMM-07
  // registry (rmmspine/Rmm07Policy.kt) — health -> rmm.monitoring,
  // patch_posture -> rmm.patch, posture -> rmm.endpoint_security,
  // encryption_report -> rmm.encryption_enforcement, drift ->
  // rmm.baselines, anomaly -> rmm.anomaly_baselining; inventory,
  // app_control and dlp already matched. Defaults are the REGISTRY
  // defaults. An unknown key FAILS CLOSED (false) instead of
  // throwing require() — a policy query must never crash a caller
  // into an arbitrary state.
  val KEYS=setOf("rmm.monitoring.enabled","rmm.inventory.enabled","rmm.patch.enabled","rmm.endpoint_security.enabled","rmm.encryption_enforcement.enabled","rmm.baselines.enabled","rmm.app_control.enabled","rmm.anomaly_baselining.enabled","rmm.dlp.enabled")
  private val DEFAULTS=mapOf("rmm.dlp.enabled" to false) // registry defaults: all others ON
  fun enabled(toggles:Map<String,Boolean>,key:String):Boolean{ if(key !in KEYS) return false; return toggles[key] ?: (DEFAULTS[key] ?: true) }
}
// ---------- RMM-01 ----------
data class EndpointSample(val atMs:Long, val storageFreePct:Double?=null, val memoryUsedPct:Double?=null,
  val batteryPct:Int?=null, val batteryCharging:Boolean?=null, val uptimeMs:Long?=null, val deskguestRunning:Boolean?=null,
  val absentSections:List<String> = listOf()) {
  fun sectionPresent(n:String)=when(n){"storage"->storageFreePct!=null;"memory"->memoryUsedPct!=null;"battery"->batteryPct!=null;"uptime"->uptimeMs!=null;"app_state"->deskguestRunning!=null;else->false}
}
interface HealthCollector{ fun collect(nowMs:Long):EndpointSample } // platform binding supplies readable sections only
enum class CondKind{STORAGE_LOW,MEMORY_HIGH,BATTERY_LOW,UPTIME_EXCEEDED,APP_DOWN,MONITOR_FAILURE}
enum class Outcome{FIRING,CLEAR,INDETERMINATE}
data class HealthCondition(val id:String,val kind:CondKind,val threshold:Double,val debounce:Int=1,val cooldownMs:Long=3_600_000)
class ConditionEvaluator{ private val streak=mutableMapOf<String,Int>()
  fun eval(c:HealthCondition,s:EndpointSample):Outcome{ val v:Double?=when(c.kind){
    CondKind.STORAGE_LOW->s.storageFreePct; CondKind.MEMORY_HIGH->s.memoryUsedPct
    CondKind.BATTERY_LOW->s.batteryPct?.toDouble(); CondKind.UPTIME_EXCEEDED->s.uptimeMs?.toDouble()
    CondKind.APP_DOWN->s.deskguestRunning?.let{if(it)0.0 else 1.0}; CondKind.MONITOR_FAILURE->null }
    if(v==null){streak[c.id]=0;return Outcome.INDETERMINATE} // gap neither raises nor clears
    val hit=when(c.kind){CondKind.STORAGE_LOW,CondKind.BATTERY_LOW->v<=c.threshold;CondKind.APP_DOWN->v>=1.0;else->v>=c.threshold}
    val n=if(hit)(streak[c.id]?:0)+1 else 0; streak[c.id]=n; return if(n>=c.debounce)Outcome.FIRING else if(hit)Outcome.INDETERMINATE else Outcome.CLEAR } }
data class HealthAlert(val deviceId:String,val conditionId:String,val atMs:Long,val detail:String)
class HealthAlertCentre(val floodCapPerHour:Int=60){ val alerts=mutableListOf<HealthAlert>(); var overflow=0; private val active=mutableSetOf<String>(); private val lastFired=mutableMapOf<String,Long>()
  fun onEval(deviceId:String,c:HealthCondition,o:Outcome,nowMs:Long,egress:(HealthAlert)->Unit):Boolean{ val k="$deviceId/${c.id}"
    if(o==Outcome.CLEAR){active.remove(k);return false}; if(o!=Outcome.FIRING)return false
    if(k in active)return false; if(nowMs-(lastFired[k]?:Long.MIN_VALUE/2)<c.cooldownMs)return false
    if(alerts.count{it.deviceId==deviceId&&nowMs-it.atMs<3_600_000}>=floodCapPerHour){overflow++;return false}
    val a=HealthAlert(deviceId,c.id,nowMs,"${c.kind} threshold=${c.threshold}"); alerts+=a; active+=k; lastFired[k]=nowMs; egress(a); return true }
  fun isActive(deviceId:String,condId:String)="$deviceId/$condId" in active }
object AvailabilityHonesty{ // background gaps named; never Windows-service continuity
  fun note(expectedIntervalMs:Long,samples:List<Long>,nowMs:Long):String{ if(samples.size<2)return "availability: insufficient samples — continuity not claimed"
    val gaps=(1 until samples.size).count{samples[it]-samples[it-1]>expectedIntervalMs*3}
    return if(gaps==0)"availability: no gaps observed in ${samples.size} samples — not a continuity guarantee (OEM battery managers may kill background work)"
      else "availability: $gaps sampling gap(s) observed — background execution interrupted (OEM battery manager or process death); gaps are named, never hidden" } }
// ---------- RMM-04 ----------
data class InventoryRecord(val deviceModel:String?,val osVersion:String?,val apiLevel:Int?,val securityPatchLevel:String?,
  val deskguestVersion:String?,val customFields:Map<String,String>,val absentSections:List<String>,
  val installedSoftwareScope:String,val installedSoftware:List<String>)
object InventoryScope{ const val SOFTWARE_LABEL="installed-software: package-visibility-limited — only DeskGuest itself and packages the platform permits this app to query; NOT a full installed-apps enumeration"
  fun build(model:String?,os:String?,api:Int?,patch:String?,deskguest:String?,custom:Map<String,String>,queryable:List<String>):InventoryRecord{
    val absent=listOfNotNull(if(model==null)"hardware.model" else null,if(os==null)"os.version" else null,if(patch==null)"os.security_patch_level" else null)
    return InventoryRecord(model,os,api,patch,deskguest,custom,absent,SOFTWARE_LABEL,queryable) } }
// ---------- RMM-02 (reporting half only) ----------
data class PatchPosture(val securityPatchLevel:String?,val osVersion:String?,val deskguestUpdateVerified:Boolean,val reportedAtMs:Long){
  val deploymentBound="third-party patch deployment: Device-Owner-bounded — at the app tier installs are installer-mediated (user-confirmed) only; silent deployment is impossible and is not claimed"
  fun summary()="security patch level: ${securityPatchLevel?:"absent — unreadable, named absent"}; OS: ${osVersion?:"absent"}; DeskGuest own-app update channel: verified signed-manifest (existing)" }
// ---------- RMM-17 (detect-tier facts only) ----------
data class PostureFacts(val osIntegrity:String,val encryptionOn:Boolean?,val deskguestProvenance:String,val deskguestAccessibilityGranted:Boolean,val deskguestOverlayGranted:Boolean){
  val tier="detect"; val behaviouralIsolation="scoped OUT on Android: a non-privileged app cannot observe or isolate other apps' behaviour — no analogue claimed"
  fun facts()=mapOf("os_integrity" to osIntegrity,"encryption_on" to (encryptionOn?.toString()?:"absent"),"deskguest_provenance" to deskguestProvenance,"deskguest_accessibility_grant" to deskguestAccessibilityGranted.toString(),"deskguest_overlay_grant" to deskguestOverlayGranted.toString()) }
// ---------- RMM-18 (state report, tri-state) ----------
data class EncryptionStateReport(val encryptionPresent:Boolean?,val encryptionOn:Boolean?,val screenLockStrength:String){
  val enforcement="impossible at the app tier — the OS owns encryption; DeskGuest reports state, it does not enforce it"
  val escrow="impossible at the app tier — no recovery key exists for an app to escrow; none is simulated"
  fun triState()="detected: present=${encryptionPresent?:"absent"} on=${encryptionOn?:"absent"} screen_lock=$screenLockStrength | enforcement: impossible | escrow: impossible" }
// ---------- RMM-19 ----------
data class Baseline(val deskguestSettings:Map<String,String>,val policyHash:String,val grantedPermissions:Set<String>,val deskguestVersion:String)
data class DriftItem(val field:String,val expected:String,val actual:String)
object DriftEvaluator{ fun evaluate(b:Baseline,cur:Baseline):List<DriftItem>{ val out=mutableListOf<DriftItem>()
    for(k in (b.deskguestSettings.keys+cur.deskguestSettings.keys)) if(b.deskguestSettings[k]!=cur.deskguestSettings[k]) out+=DriftItem("deskguest_setting.$k",b.deskguestSettings[k]?:"absent",cur.deskguestSettings[k]?:"absent")
    if(b.policyHash!=cur.policyHash)out+=DriftItem("policy_state",b.policyHash,cur.policyHash)
    if(b.grantedPermissions!=cur.grantedPermissions)out+=DriftItem("granted_permissions",b.grantedPermissions.sorted().joinToString(","),cur.grantedPermissions.sorted().joinToString(","))
    if(b.deskguestVersion!=cur.deskguestVersion)out+=DriftItem("app_version",b.deskguestVersion,cur.deskguestVersion); return out }
  fun asCondition(d:List<DriftItem>) = if(d.isEmpty())Outcome.CLEAR else Outcome.FIRING } // feeds RMM-01 alert path via HealthAlertCentre
// ---------- RMM-25 ----------
enum class OwnershipTier{DEVICE_OWNER,PROFILE_OWNER,PERSONAL,UNKNOWN}
enum class CapabilityLevel{ENFORCE,DETECT,IMPOSSIBLE}
object AppControlTiers{ fun level(t:OwnershipTier):CapabilityLevel=when(t){OwnershipTier.DEVICE_OWNER->CapabilityLevel.ENFORCE;OwnershipTier.PROFILE_OWNER->CapabilityLevel.DETECT;OwnershipTier.PERSONAL,OwnershipTier.UNKNOWN->CapabilityLevel.DETECT}
  fun wording(t:OwnershipTier)="tier=$t capability=${level(t)} — personal tier is detect + report only; enforcement is never claimed where capability is DETECT or IMPOSSIBLE"
  const val REQUEST_WORKFLOW="request workflow: hub-side only — no Android mirror; requests are decided on the hub" }
// ---------- RMM-27 ----------
sealed class AnomalyVerdict{ object StillLearning:AnomalyVerdict(); data class Normal(val metric:String):AnomalyVerdict(); data class Anomaly(val metric:String,val sustained:Int):AnomalyVerdict() }
class AnomalyBaseliner(val minSamples:Int=20,val minSpanMs:Long=86_400_000,val bandSigma:Double=3.0,val sustainedNeeded:Int=3){
  private val hist=mutableMapOf<String,MutableList<Pair<Long,Double>>>()
  fun add(metric:String,atMs:Long,v:Double){hist.getOrPut(metric){mutableListOf()}+=atMs to v}
  fun verdict(metric:String):AnomalyVerdict{ val h=hist[metric]?:return AnomalyVerdict.StillLearning
    if(h.size<minSamples||h.last().first-h.first().first<minSpanMs)return AnomalyVerdict.StillLearning // immature: no verdicts
    val vs=h.map{it.second}; val mean=vs.average(); val sd=Math.sqrt(vs.map{(it-mean)*(it-mean)}.average())
    if(sd==0.0)return AnomalyVerdict.Normal(metric)
    var streak=0; for(v in vs) streak=if(Math.abs(v-mean)>bandSigma*sd)streak+1 else 0
    return if(streak>=sustainedNeeded)AnomalyVerdict.Anomaly(metric,streak) else AnomalyVerdict.Normal(metric) }
  fun honesty()="profile maturity is reported with every verdict; an immature profile says 'still learning' and issues no verdict" }
// ---------- RMM-32 (default OFF, metadata-only) ----------
enum class DlpKind{EMAIL,CARD_LIKE,SSN_LIKE,PHONE_LIKE}
data class DlpFinding(val kind:DlpKind,val fileHash:String,val count:Int) // metadata only: no raw value field exists
object DlpClassifier{ private val pats=mapOf(DlpKind.EMAIL to Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"),
    DlpKind.CARD_LIKE to Regex("\\b(?:\\d[ -]?){13,16}\\b"), DlpKind.SSN_LIKE to Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b"), DlpKind.PHONE_LIKE to Regex("\\b\\d{3}-\\d{3}-\\d{4}\\b"))
  fun sha(s:String)=MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString(""){"%02x".format(it)}
  fun scan(name:String,text:String):List<DlpFinding>{ val out=mutableListOf<DlpFinding>(); for((k,p) in pats){val n=p.findAll(text).count(); if(n>0)out+=DlpFinding(k,sha(name),n)}; return out } }
object DlpScope{ const val SCOPE="scan scope: DeskGuest's own storage + folders the user explicitly granted — nothing else is reachable, by platform sandbox design"
  val UNSEEABLE=listOf("other apps' private storage","messages in other apps","browser content","system partitions")
  fun surfaceNote()="$SCOPE; unseeable channels (named, not implied covered): ${UNSEEABLE.joinToString(", ")}" }
class DlpEngine(val toggles:Map<String,Boolean>){ fun scan(files:Map<String,String>):List<DlpFinding>{
  if(!RmmToggles.enabled(toggles,"rmm.dlp.enabled"))return emptyList() // default OFF
  return files.flatMap{(n,t)->DlpClassifier.scan(n,t)} } }

// ---------- RMM-26 software licence states (parity mirror, W3 lane B) ----------
/** Mirrored from the Windows rename (bd-shared-rmm-3 F11, W2-B): the old
 *  names said the opposite of what they meant — "over-licensed" was used
 *  for installed > entitled, which is a DEFICIT of licences. Canonical
 *  values are "deficit"/"surplus"; the old constant NAMES survive as
 *  aliases carrying the CORRECTED values, exactly as the Windows
 *  LicenceStates class does. The compliance export counts key is
 *  `deficit_lines` (never `over_licensed_lines`). Android has no metering
 *  engine of its own (only the `rmm.metering.enabled` policy key exists),
 *  so this is the vocabulary + export-shape mirror — not a metering
 *  implementation, and nothing here claims one. */
object LicenceStates {
  const val Compliant = "compliant"
  const val Deficit = "deficit"   // installed > entitled
  const val Surplus = "surplus"   // installed < entitled
  const val UnlicensedUnknown = "unlicensed_unknown"
  const val UnknownEdition = "unknown_edition"
  const val EntitledNotInstalled = "entitled_not_installed"
  const val OverLicensed = Deficit   // legacy alias, corrected value
  const val UnderLicensed = Surplus  // legacy alias, corrected value

  /** The compliance export counts shape for metering lines. */
  // W12-DS P7-F24: every declared state has a bucket, so the
  // buckets reconcile with total_lines.
  fun exportCounts(lineStates: List<String>): Map<String, Int> = mapOf(
    "total_lines" to lineStates.size,
    "compliant_lines" to lineStates.count { it == Compliant },
    "deficit_lines" to lineStates.count { it == Deficit },
    "surplus_lines" to lineStates.count { it == Surplus },
    "unlicensed_unknown_lines" to lineStates.count { it == UnlicensedUnknown },
    "unknown_edition_lines" to lineStates.count { it == UnknownEdition },
    "entitled_not_installed_lines" to lineStates.count { it == EntitledNotInstalled },
    "other_lines" to lineStates.count { it !in setOf(Compliant, Deficit, Surplus, UnlicensedUnknown, UnknownEdition, EntitledNotInstalled) }
  )
}
object LicenceFindingKinds {
  const val KindDeficit = "deficit"
  const val KindSurplus = "surplus"
  const val KindOverLicensed = KindDeficit   // legacy alias
  const val KindUnderLicensed = KindSurplus  // legacy alias
}
/** The export counts shape for metering lines (pure; suite-pinned).
 *  A member of [LicenceStates] rather than a file-level function:
 *  the chunked JVM build's file-facade metadata for this file did
 *  not surface a top-level function to downstream compiles
 *  (observed 2026-11-22, W3 lane B; object members resolve). */
