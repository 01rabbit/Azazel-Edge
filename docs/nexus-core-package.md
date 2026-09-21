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

## 7. Building it

```sh
cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml
python3 packaging/nexus-core/nexus_core_package.py --out dist/nexus-core
```

Nothing under `installer/`, `security/` or `systemd/` is read or written.

## 8. What this does not establish

- **That the payload runs correctly on target hardware.** It builds and
  self-checks; that is all.
- **That the digest is authentic.** §3.
- **`edge-baseline-ready`.** §2.
- **Anything about a real network.** The package configures none, and nothing
  here was exercised against one.
