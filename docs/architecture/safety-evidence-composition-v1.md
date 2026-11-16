# Additive historical safety evidence composition v1

Tracking #400/#393. Base61d64119e9be101a1382efd3efa37d3907529417.
Conditions and literal acceptance matrix are fixed before implementation.

## Authority and trust boundary

Call the existing four-category evaluate_safety_observations FIRST, unchanged,
using original contract/observations and externally supplied key/checkpoint pins.
Invalid main still raises its original error. Preserve exact main_evaluation,
including verified positives and claimed structural zero/null values. Supplements
NEVER modify main categories, opportunities, counts, scope, keys or provenance.
No runtime/control/provider/AI/benefit gate is modified. New pure additive wrapper
plus Root-enrolled readonly file intake, not a new qualification framework.

Seven explicit families: forged_refusal_v1,forged_refusal_v2,advisory_exec,
authority_ingress,postconnect_refusal,postconnect_authorization,natural_close_recv.
Reuse each original strict verify API; never coerce oldformats or fake an oldplan.
Refusal/copy/recvreturn and sampled-state facts retain their exact original result.
Natural-close peer pairing and paired refusalconsistency remain null. Hashes only
bind bytes; no sameevent, simultaneouscapture, independentcustody, scope/identity
or causal relationship to main follows from shared fields/plan attachment.
Every supplemental relation is historical_reference_only/scope_binding_unestablished.

## Pure input and output contract

API evaluate_safety_evidence_composition(contract_raw,observations_raw,*,
safety_pins,composition_plan_raw=None,expected_composition_plan_sha256=None,
supplements=None). Main first. New plan edge-safety-evidence-composition-plan/v1,
canonicalJSON+LF <=128KiB, exact schema_version/main_contract_sha256/entries.
entries list0..64; each exact id,kind,sha256. IDboundedref unique; kindwhitelistabove.
sha256 is exact per-family FLAT artifactslot map, values lowercasehex64 or null.
Allitems require plan rawbytes and non-null externalplan/evaluation pins; submitted
evaluation rawbytes may be absent/malformed/hash-mismatched without blocking
independently valid originalmeasurement replay. Missingmeasurement
slots allow null and mustmatch originalplan/parser's own missing semantics.
Wholebundle <=64MiB submitted originalbytes; eachleafbound at most1MiB except
plan/trust32KiB and probe/governance/stdout/stderr/reference64KiB, evaluation1MiB.
No bool/float/integer/type substitution, duplicateIDs/keys/unknownkinds/extra slots.
A missing/invalid optional globalplan preserves main and reports planunavailable/
invalid; no inferredentries or guessedformat. No supplementaryI/O/execution/clocks.

supplements maps declaredID to flat slot->bytes-or-null. Forged slots plan,trust,
before_source,before_journal,before_anchors,after_source,after_journal,after_anchors,
stdout,stderr,evaluation (+reference_frame onlyv2). Advisory slots plan,probe,
governance,audit,evaluation. Remainingfourfamilies slots plan,probe,sot_before,
sot_after,audit_before,audit_after,evaluation. Nestedbefore/after dictionaries
are assembled ONLY to call exactexistingforge API, never rewriteplans or bytes.
Otherfamilies receive their original rawarguments. Expectedplanhash externally
fixed bymanifest. Exact declaredartifacthashes checked before reuse. Refusal/empty
stderr/empty audit remains real bytes, distinct from absentnull. Do notparse
unknowninputs as a successful zerocount.

Each independentitem contains id,kind,evidence_relation,raw_sha256,
replayed_evaluation,published_evaluation,published_evaluation_matches,reasons,status.
Originalpublished evaluation is canonicalJSON+LF boundedobject, pinned externally;
replay exact originalverifier and compare parsedcanonicalvalues. Preserve original
published diagnostic separately, never trust its caller flags/counts. Mismatch
makes itemunknown but retains independently computed originalfacts; unavailable or
malformed optionalartifact affects only thatitem, preserving valid siblings/main.
If published JSON is invalid, preserve its pin but decodedpublishedvalue=null;
valid originalreplay may stillsurvive. File/pin/schema/missing reasons explicit.
No sourcebyte/historyrepair, syntheticreplacement or writes.

Output edge-safety-evidence-composition/v1: exact main_evaluation; supplemental
items; category_diagnostics for fouroriginalcategories; comparison_eligibility=false,
comparison_status=WITHHELD; qualified_safety_count=null; all safety.FLAGSfalse.
Categorydiagnostics contain original maincategory (unchanged), supplementIDs,
observation_layers, unmeasured_reasons, qualified_safety_count=null,
independently_measured=false. They do NOT generate supplementalviolationcount0
or inventopportunitydenominators. Base positives survive malformedoptional inputs.

Categorymap is descriptive only: forge→forged_evidence_accepted;
advisory_exec→advisory_authority_conversion; authority/refusal/auth/naturalclose→
unauthorized_action. No #601–607 family is an independentlyqualified protected
networkdelivery channel; protected_escape stays explicitabout thatgap, while its
existingmaincategory is preserved. Selectedlayer labels describe finitechallenge,
execattempt,connection,protocolcopy,refusalresponse,individualrecvreturn and sampled
originalstate, not generalabsence or whole-window coverage.

Comparisonblockers are explicit fixed conditions: independent_safety_qualification_
unavailable; supplemental_main_event_binding_unestablished; full_window_coverage_
unestablished; source_collector_custody_not_proven_by_hashes; comparative_timing_
and_assignments_not_validated; causal_benefit_not_established. Add dynamic missing/
invalid/mismatched-supplement reasons. Scopeacceptance limits separately record
internalbranch/userspaceconsumption, transient/allpersistentstate, production
Root/Web/advisory/keys, Pi/HIL/physical/performance. No numeric diagnostic threshold
can remove these blockers. Existing98%/1.2x and5ms timing unchanged.

## Readonly collection

New collect_safety_evidence_composition(composition_enrollment_path,*,
expected_composition_enrollment_sha256,expected_composition_plan_sha256).
Enrollment edge-safety-evidence-composition-enrollment/v1 canonical<=128KiB exact
schema_version,reader_uid,kernel_boot_id,safety,composition_plan_path,supplements.
safety exact enrollment_path,enrollment_sha256,checkpoint_sha256. supplements
maps IDs to exactflat slot physicalpaths-or-null matchingplanhashslots. External
SHA binds wholeenrollment. Nonrootactualregisteredreader/currentboot, distinct
physicalpaths/no symlinks, Root0444singlelink/protectedancestors and readonlyheldFD
metadata/allclosefences. Main must pass unchanged collect_registered_safety with
originalenrollment+checkpoint; preserve its exact base_collection. Holdmain and
present supplementaryoriginals through evaluation+finalfences, use exactoriginal
mainraw/pins from its registeredfiles. Call publicpurewrapper and verify its main
matchesbase_collection.evaluation. No trusting precomputed approval flags.

No optional filefailure may mutate/hide alreadyvalidatedmain/otherpurefacts;
unsafe fileenrollment/reader/digest/metadata/close refuses the NEW collection
as in existingstrictcollectors; earlierpublishedmain/standalone results remain
unchanged. Missing artifacts are explicitnullonly, never a failedread replaced
with emptybytes. Reader differs from supplement actors/producers/consumers and
servers where originalschema requires; no extra DAC/ptrace/user/group privileges.
Historical copiedMacarchives cannot satisfy currentRoot/currentboot intake: replay
is an explicitofflinepurepath and never a newkernel/enrollment/independence claim.

## Fixed tests and gates

Corpusmatrix covers all7families through originalrealpureevaluators; valid,
missing, badpin/schema/wrongkind/duplicate/globalbadplan, originalpublishedmismatch,
rawreadonly and originalmainpositivepreservation; allrefusal/recvsuccess never
changesbasecounts/qualification/comparison. NaturalclosepairNone andpartial/death/
linkloss/knownauditchange+missingSoT retainedexactly. Forgeko Source/anchors cannot
be replaced with assertions. Readonlyintaketests cover currentboot/UID/actor role,
paths/symlinks/metadata/hash/close and explicitabsence. Syntheticdata is labelled.
Existing63/45/etc publishedactualarchives replay separately with exactexternalpins
and originals unchanged; anysyntheticmain joining them is declaredsynthetic and
historical-only, never simultaneousfour-category observation or comparison.
Run focusedregressions and existingbase/adapter tests, independentreview, PR,
allfinalheadCI and exactbase/head/tree before conditionalmerge. No newkerneltrial
is necessary for this pureintegration; no unchangedsensor trial rerun as proof.
No production/serviceactivation/keys/restrictedpaths/newIssue/privilege change.

## Preimplementation clarification: independent report and measurement failures

Validatepublishedreport integrity separately from measurement artifacts. Missing,
malformed or mismatched publishedreport makes itemunknown but cannot suppress a
valid originalreplay. For a missing/bad-hash measurement slot, keep originalbytes/
actualdigest untouched in caller storage and record the exactquarantinedslot;
pass explicitNone (unavailable) to its existing verifier, which may preserve other
valid samples/copies using its own missing rules. Never feed unpinned bytes,
repair a plan, manufacture emptybytes, or synthesize a replacement measurement.
Invalid plan/trust/globalrequiredidentity may refuse thatoriginalreplay. This is
inputquarantine, not historyrepair or an observation of the missing event.

The collector permits the explicit evaluation-path null exception while its
external expectedpublishedpin remains mandatory. A PRESENT path always uses
strictread/hash checks; failure is never converted to null. This gives the pure
wrapper an honestly declared unavailable report while retaining validmeasurement
replay. Other paths keep originalabsence/pin consistency and sealedintake rules.

## Precollection compatibility and actual-file boundary controls

Originalpublished diagnostics use their original boundedcanonical object parser,
not the maincontract's unrelated256-byte stringlimit: valid256-bytecopy/512hex and
finite numeric originalreports survive. Canonicaltyped comparison distinguishes
False/0,True/1,integer/float. Originalplan/trust rolechecks use each family's own
parser. Category-specific interpretationgaps and observation_layers_status=
family_capabilities_not_observed_coverage prevent capabilitylabels being mistaken
for actual measuredcoverage.

Seven isolated offlineLinux file-intake controls use SYNTHETIC signedmain and
SYNTHETIC natural-close plans/metadata/public TESTkeys. Actual facts tested are
Root0444files, distinctcap0+NNP UID61002 reading, protectedpaths, strictboot/reader/
metadata gates and unchangedoriginalbytes; NOT actual packets/newkernelcapture or
productionidentity/keyindependence. Cases: completehistoricalreference; declared
missingpublishedreport with nonnullpin; separatelypinned changedpublishedreport;
missingafterSoT retainingknownauditchange; wrongreader; writableleaf; wrongboot.
Only fixturecontroller writes/stages/removes its own temporaryfiles. Guard reader
against writeopens, mutations, sockets and subprocesses afterimports; compare all
originalhashes before/after. Existingouter setup UID/GID capability subsetonly,
no BPF/NET_ADMIN/newpermission required. Required CIUID stage must run all7, not
skip-as-pass. No new accounts/services/productionkeys or sensors.
