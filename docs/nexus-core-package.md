# The x86_64 Edge Core package Azazel-Nexus verifies

Status: **implemented** (`packaging/nexus-core/nexus_core_package.py`,
`tests/test_nexus_core_package_v1.py`). This is [Edge#424](https://github.com/01rabbit/Azazel-Edge/issues/424),
raised from [Azazel-Nexus#25](https://github.com/01rabbit/Azazel-Nexus/issues/25)
and consumed by [Azazel-Nexus#44](https://github.com/01rabbit/Azazel-Nexus/issues/44).

## 1. It has nothing to do with `installer/`

Nexus does not change network configuration when it installs anything. **The
existing Edge network installer is neither used nor ported here.** The
packager takes an already-built binary and a fixed set of configuration files
and writes one artifact plus a manifest. It configures no network, touches no
interface, and installs nothing.

`tests/test_nexus_core_package_v1.py` asserts the packager references none of
`installer/internal`, `nmcli`, `iptables` or `nft`.

## 2. What Nexus looks at, and what it may conclude

Nexus verifies five things and nothing else:

| item | established by |
| --- | --- |
| the package is present | the artifact exists locally |
| the version matches | `manifest.version`, and the binary's own `--version` |
| the digest matches | `manifest.digest` re-derived from the artifact |
| the health contract answers | running `bin/azazel-edge-core --health` |
| the payload is running | **not by this package** — see §5 |

**Accepting the package establishes at most the first four.** The manifest
says so in its own `not_established_by_accepting_this_package` field, and a
test asserts that field mentions both *running* and *edge-baseline-ready*.

`edge-baseline-ready` needs all five together. A package on disk is not a
running Edge, and this artifact never claims to make it one.

## 3. The digest is **not signed**

Edge#424 asks for this to be explicit, because Nexus distinguishes *the tag is
signed* from *the digest is signed*.

**Neither is true here.** Signing-key operations are out of scope for this
artifact. The manifest carries `"signed": false` and the reason.

What an unsigned digest establishes is **integrity against accidental
change** — a truncated download, a half-written file, the wrong build copied
into place. What it does not establish is integrity against an adversary who
can rewrite the package and the manifest together. A consumer must degrade
rather than read it as authenticity.

## 4. Deterministic, because a digest is being compared

The same inputs produce byte-identical output: sorted archive entries, zeroed
mtimes, zeroed uid/gid, empty uname/gname, fixed modes, and a gzip header with
no timestamp. Each of those is a place a build host would otherwise leak into
a digest Nexus is about to compare.

The payload is **listed, never globbed**. A package whose contents depend on
the state of a working copy is a package whose digest means something
different on every machine.

The builder also runs the binary's `--version` and refuses if it disagrees
with `Cargo.toml`. A binary built from a different checkout than the manifest
being written is the one mistake a digest cannot catch, because both would be
internally consistent.

## 5. The health contract

**A fixed CLI contract, not network HTTP.** `bin/azazel-edge-core --health`
prints JSON on stdout and exits.

```json
{
  "contract": "azazel-edge-core/health/v1",
  "status": "healthy",
  "version": "0.1.0",
  "observe_only": true,
  "checks": [{"name": "enforcement_disabled", "ok": true, "detail": "AZAZEL_DEFENSE_ENFORCE=false"}]
}
```

**Healthy requires all four of:** the process exits 0, stdout parses as JSON,
its `contract` equals the contract string, and its `status` is `healthy`. All
four, because a truncated or garbled stdout must not be able to read as
healthy — which is the condition Edge#424 asks for by name.

**Anything unevaluated is unhealthy.** A check that cannot be run reports
`ok: false` with the reason. No path omits a check and still reports healthy,
because a reader counting green checks would not notice one missing.

**The check is one-shot and reads nothing, writes nothing, opens no socket and
starts no loop.** A health check that changed the node would be a health check
nobody could run.

**It establishes the binary, never the daemon.** It proves this executable is
present, is this version, and can evaluate its own posture. It says nothing
about whether anything is running, so Nexus determines that separately.

### The posture checks

| check | fails when |
| --- | --- |
| `enforcement_disabled` | `AZAZEL_DEFENSE_ENFORCE` is on |
| `dry_run` | `AZAZEL_DEFENSE_DRY_RUN` is off |
| `advisory_level` | `AZAZEL_DEFENSE_ENFORCE_LEVEL` is not `advisory` |
| `high_impact_auto_disabled` | `AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO` is on |
| `redirect_policy_not_enforcing` | enforcement is on |

Each is exercised on its own by a test. **A check nothing can make fail is a
check that is always green, which is indistinguishable from a check that is
not there.**

## 6. Observe-only, by declaration and by default

The manifest's `posture` declares `observe_only: true` and all of
`enforcement`, `redirect`, `external_device_change` and
`network_configuration_change` false. `startup.observe_only_env` ships the
environment that makes it so, so a consumer can check the posture it is being
asked to run rather than trusting that a default stayed a default.

The package **starts nothing**. It declares how a supervisor should start the
payload; bringing it up is the consumer's service manager's job.

## 6b. The contract Nexus pins

Azazel-Nexus verifies this package **without importing the packager**. The two
repositories build and test separately, and a consumer that needed the
producer's source in its own CI would be sharing an implementation rather than
verifying a contract.

So the shape is exported to `packaging/nexus-core/contract/`, three small JSON
documents that both repositories commit:

| file | what it fixes |
| --- | --- |
| `pin.json` | package name, version, architecture, both contract strings, the artifact and manifest filenames, `signed: false`, and what a consumer must do |
| `manifest-schema.json` | every field of the manifest, as sorted dotted paths |
| `health-schema.json` | every field of the health report, the posture check names, the healthy and unhealthy status words, and the four conditions |

**They carry no digest and no timestamp.** That is what lets them stay
byte-identical across rebuilds -- a contract that changed every time the
binary was recompiled would be re-approved so often that nobody would read the
diff. A change to one of these files always means the contract changed.

Both schemas are **derived, not restated**: the manifest schema from
`manifest_document`, the health schema by running the binary. A hand-written
schema is a second description of the same thing, and the first time the two
disagree it is the consumer that breaks, believing it verified something.

The health schema is derived from **two** runs -- the observe-only default and
one with enforcement enabled -- because the unhealthy branch has to be
observed rather than asserted. Regeneration refuses if enforcement does not
produce an unhealthy report and a non-zero exit, if the two reports differ in
shape, or if the built binary disagrees with the tree's version.

```sh
python3 packaging/nexus-core/nexus_core_package.py --emit-contract
```

`tests/test_nexus_contract_export.py` regenerates into a temporary directory
and asserts the committed files are byte-identical, so a field added to the
manifest cannot reach a package without also reaching the contract.

## 7. Building it

```sh
cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml
python3 packaging/nexus-core/nexus_core_package.py --out dist/nexus-core
```

Nothing under `installer/`, `security/` or `systemd/` is read or written.

After changing anything the manifest or the health report carries, regenerate the contract (§6b) in the same commit.

## 8. What this does not establish

- **That the payload runs correctly on target hardware.** It builds and
  self-checks; that is all.
- **That the digest is authentic.** §3.
- **`edge-baseline-ready`.** §2.
- **Anything about a real network.** The package configures none, and nothing
  here was exercised against one.
