# Offline audit of pinned recorded-provider archives — #400/#393

Freeze before implementation; base747e8784 (#598). Productize the bounded,
read-only OFFLINE audit previously performed on the published public CI archive.
No live acquisition, queries, imports from test harness, extraction, network,
keys/signing, service/capability/policy/runtime authority or evidence rewriting.
No installer/security/systemd or production changes.

## External trust and inputs

New pure evaluate_provider_restoration_archive(archive_raw,*,
expected_archive_sha256), error ProviderRestorationArchiveError(ValueError).
The caller MUST externally pin original ZIP SHA256; the archive's own manifest is
not self-authentication. Verify ZIP bytes BEFORE decoding. External digest proves
only identity of enrolled bytes, not GitHub origin/Root custody/kernel/source truth,
producer/witness independence, freshness or execution facts. All source/query
metadata remains the existing externally trusted recorded-lab premise.

Accept only bounded v1 normal ZIP: <=32MiB compressed, exact25 entries, <=64MiB
uncompressed total, each<=32MiB, ASCII exact allowed flat filenames from #598's
24PUBLIC file allowlist plus collection-hashes.json. Require unique exact inventory,
no directories/links/path traversals/encryption/multi-disk/ZIP64/comments/unknown
compression. STORED/DEFLATED only. Validate bounded EOCD count/central-size/offset
BEFORE constructing ZipFile (prevent malicious huge entry allocation), CRC and all
per-entry declared/read sizes. No extraction or trust in ZIP file ownership modes.
The original actual artifact13980483923 is standard ZIP25/deflate/no-comment,
compressed20449/uncompressed52458 bytes, SHA
52e287e1ce49bdf3845f05cd969481e688ddb2d521b6c624ca4f5f39d6ef9dee.

## Required consistency and unchanged evaluation

Strict bounded JSON parsing/typed equality, reject duplicate/deep/nonfinite input.
Manifest exact schema_version=edge-provider-artifact-copy/v1,files,errors; errors
MUST empty; files exact24names, each exactsha256/bytes with strictint lengths/hash.
Use existing Source-proof and recorded-NFT evaluator unchanged with original
contract/source-plan/restoration-plan/derived-policy/source-final/receipt bytes.
Recomputed diagnostic must equal published result by full typed canonical equality;
never trust published pass, modify old inputs or manufacture absent evidence.

Verify original-policy canonicalNO-LF, derived EXACToriginal+LF, same TrustPolicy
semantic digest and provenance original/derived hashes/DERIVEDlabel; unused explicit
public observer pin matches contract and role label, creates no observations.
Provenance originalprefix/finalSource hashes and selected originalLFframe sequence/
hash must match Source/restoration plans and actual bytes. Original prefix is exact
original final prefix; checkpoints match original Source-proof plan. Labels are
recorded assertions, never custody/independence attestation.

For each phase, original child JSON (not normalized/replaced) must equal receipt
minus ONLY parent-added actual_child_argv/source/capture_boundary; original child
stderr empty. Parent launch exactargv/PID/expectednetns must match receipt/plan.
All24files remain unchanged. Existing evaluator handles exact owner/context/time/
full typed chain comparisons; missing/changed/counterdrift is not repaired orzeroed.
Archive inconsistency refuses a NEWaudit result, preserving original bytes.

New result edge-provider-restoration-archive-audit/v1 contains
archive_sha256,archive_integrity_verified=true,archive_origin_authenticated=false,
replay_matches_published=true,replayed_diagnostic(originalresult),
network_mechanism_restored=null,qualified_safety_count=null,
execution_fact_verified=false,independently_measured=false, all safety.FLAGSfalse.
Archive integrity never promotes the nested recorded diagnostic into broader proof.

## Fixed data and acceptance

Retain original public actual ZIP as immutable fixture with its external SHA and
source CI/run/artifact IDs; no private keys. Actual fixture replay is HISTORICAL
OFFLINE evidence, never a fresh kernel trial. Synthetic repacks/mutations explicitly
marked synthetic: wrong externalpin, inventory/duplicates/traversal/link/encryption/
ZIP64/count/size/CRC/bomb bounds, manifest errors/hash/types, policy derivation,
Source prefix/checkpoints/selectedframe/provenance, child/launch/stderr/receipt
bindings and published-result tampering. No I/O/extraction/query/network by pureAPI.

Appropriate regression/independentreview/finalheadcompleteCI/exactrefs/tree before
conditionalmerge. No new actual environment is needed. Production origin/custody,
continuous/all-network restoration, physical/Pi-HIL/safety/causal benefit,
observerobject disappearance(noSYS_ADMIN), missing-data/backfill/resume stay open.

## Candidate validation

89 archive cases pass: the one byte-identical historical public ZIP replays its
published diagnostic; all mutations/repacks are explicitly SYNTHETIC and separately
repinned. Review found scalar/list JSON could escape as AttributeError; exact
object checks and24 typed-object regressions close this error boundary. Root
resource review moved the original validated policy's byte/record bounds BEFORE
Source line indexing and rejects rawCR (canonical escaped JSON\\r stays valid),
with LF-budget and bareCR preallocation regressions. No new Source is signed.

Existing recorded-restoration63 cases also pass:152 combined relevant cases.
Static/diff checks and independent review passed; no new environment or kernel
capture was executed locally. Historical replay adds no current restoration,
custody or safety acceptance. Final-head complete CI and exact refs/tree remain
required before conditional merge.
