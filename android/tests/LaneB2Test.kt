import io.agenticcontrol.app.rmm.*
private var failures=0; private fun check(n:String,c:Boolean){ if(c)println("PASS  $n") else {println("FAIL  $n");failures++} }
fun main(){
 // RMM-01
 val ev=ConditionEvaluator(); val cond=HealthCondition("stor","STORAGE_LOW".let{CondKind.STORAGE_LOW},10.0,debounce=2)
 check("R01 indeterminate on absent reading",ev.eval(cond,EndpointSample(0,storageFreePct=null,absentSections=listOf("storage")))==Outcome.INDETERMINATE)
 check("R01 debounce needs 2 hits",ev.eval(cond,EndpointSample(1,storageFreePct=5.0))==Outcome.INDETERMINATE && ev.eval(cond,EndpointSample(2,storageFreePct=5.0))==Outcome.FIRING)
 val centre=HealthAlertCentre(floodCapPerHour=2); var sent=0; val c1=HealthCondition("a",CondKind.MEMORY_HIGH,90.0)
 repeat(5){centre.onEval("dev",c1,Outcome.FIRING,it*4000_000L){sent++}}
 check("R01 dedup+cooldown+flood: <=cap egress",sent in 1..2)
 check("R01 gap does not clear active alert", run{ val cc=HealthAlertCentre(); cc.onEval("d",c1,Outcome.FIRING,0){}; cc.onEval("d",c1,Outcome.INDETERMINATE,1000){}; cc.isActive("d","a") })
 check("R01 availability names gaps, no continuity claim",AvailabilityHonesty.note(1000,listOf(0,1000,9000),10000).contains("gap") && AvailabilityHonesty.note(1000,listOf(0L,1000L),2000).contains("not a continuity guarantee"))
 // RMM-04
 val inv=InventoryScope.build("Pixel",null,35,"2026-01-05","0.4.9",mapOf("site" to "x"),listOf("io.agenticcontrol.app"))
 check("R04 absent OS named",inv.absentSections.contains("os.version")); check("R04 software scope labelled",inv.installedSoftwareScope.contains("package-visibility-limited"))
 // RMM-02
 val pp=PatchPosture("2026-01-05","16",true,0); check("R02 patch level reported",pp.summary().contains("2026-01-05")); check("R02 deployment bound named Device-Owner",pp.deploymentBound.contains("Device-Owner-bounded"))
 check("R02 absent patch named absent",PatchPosture(null,"16",true,0).summary().contains("absent"))
 // RMM-17 / 18
 val pf=PostureFacts("verified",true,"release-key",true,false); check("R17 detect tier + isolation scoped OUT",pf.tier=="detect"&&pf.behaviouralIsolation.contains("scoped OUT"))
 val er=EncryptionStateReport(true,true,"strong"); check("R18 tri-state impossible enforcement+escrow",er.triState().contains("enforcement: impossible")&&er.escrow.contains("impossible"))
 // RMM-19
 val b=Baseline(mapOf("a" to "1"),"h1",setOf("CAMERA"),"0.4.9"); val cur=Baseline(mapOf("a" to "2"),"h1",setOf("CAMERA","MIC"),"0.4.9")
 val drift=DriftEvaluator.evaluate(b,cur); check("R19 drift finds setting+permission, not unchanged",drift.size==2&&DriftEvaluator.asCondition(drift)==Outcome.FIRING)
 check("R19 no drift = clear",DriftEvaluator.evaluate(b,b).isEmpty())
 // RMM-25 destruction: personal tier must never yield ENFORCE
 check("R25 personal=DETECT only",AppControlTiers.level(OwnershipTier.PERSONAL)==CapabilityLevel.DETECT && AppControlTiers.level(OwnershipTier.UNKNOWN)==CapabilityLevel.DETECT)
 check("R25 request workflow hub-side named",AppControlTiers.REQUEST_WORKFLOW.contains("hub-side"))
 // RMM-27
 val an=AnomalyBaseliner(); repeat(5){an.add("battery",it*1000L,50.0)}; check("R27 immature profile: still learning, no verdict",an.verdict("battery") is AnomalyVerdict.StillLearning)
 val an2=AnomalyBaseliner(minSamples=5,minSpanMs=1000); for(i in 0 until 60)an2.add("m",i*1000L,50.0+(i%2)); repeat(3){an2.add("m",(60+it)*1000L,99.0)}
 check("R27 sustained outside band = anomaly",an2.verdict("m") is AnomalyVerdict.Anomaly)
 // RMM-32 destruction: raw values must never appear in findings; default OFF
 check("R32 default OFF scans nothing",DlpEngine(emptyMap()).scan(mapOf("f" to "a@b.com")).isEmpty())
 val finds=DlpEngine(mapOf("rmm.dlp.enabled" to true)).scan(mapOf("notes.txt" to "contact a@b.com or 123-45-6789"))
 check("R32 findings metadata-only (no raw value in any field)",finds.isNotEmpty() && finds.none{it.toString().contains("a@b.com")||it.toString().contains("123-45-6789")})
 check("R32 unseeable channels named",DlpScope.surfaceNote().contains("unseeable"))
 // Toggles: unknown key fails CLOSED.
 // REPAIRED by laneW2-andfix1 (bd-and-rmm F2, 2026-11-22),
 // disclosed: the old assertion pinned require()-throws behaviour.
 // A policy query that throws can crash a caller into an arbitrary
 // state; the fixed RmmToggles fails closed (false) on unknown
 // keys, and its KEYS are the RMM-07 registry keys.
 check("Policy unknown toggle fails closed (no throw)",!RmmToggles.enabled(emptyMap(),"rmm.nope") &&
   RmmToggles.enabled(emptyMap(),"rmm.monitoring.enabled") && !RmmToggles.enabled(emptyMap(),"rmm.dlp.enabled"))
 println(if(failures==0)"LANEB2 ALL PASS" else "LANEB2 FAILURES=$failures"); if(failures>0)kotlin.system.exitProcess(1) }
