# Release Verification Guide

This guide documents lightweight release verification practices for Azazel-Edge.

## Verify checksums

When CI publishes `release-checksums.sha256`, verify local files with:

```bash
sha256sum -c release-checksums.sha256
```

At minimum, verify:
- `installer/internal/install_all.sh`
- `installer/internal/install_migrated_tools.sh`
- `installer/internal/install_ai_runtime.sh`

## Verify SBOM and dependency scan artifacts

CI uploads:
- `sbom-runtime.cdx.json` (CycloneDX)
- `pip-audit-runtime.json` (dependency vulnerability baseline)

Review both artifacts before promoting a release to field deployment.

## Recommended maintainer practices

- Use signed tags for release points.
- Keep release notes linked to merged PRs and issue IDs.
- Keep `docs/CHANGELOG.md` updated per release.

## Scope note

This project currently uses a practical baseline and is not claiming full SLSA or enterprise signing compliance.

## Optional integration smoke checks

Sensor installer and unit verification:

```bash
bash -n installer/internal/install_sensors.sh
systemd-analyze verify systemd/azazel-edge-snmp-poller.service
systemd-analyze verify systemd/azazel-edge-netflow-receiver.service
```

When `ENABLE_VECTOR=1` is used during installation:

```bash
systemctl is-active azazel-edge-vector
vector --version
test -f /etc/azazel-edge/vector/vector.toml
```

When Wazuh Agent is installed via `installer/internal/install_wazuh_agent.sh`:

```bash
systemctl is-active wazuh-agent
test -x /var/ossec/active-response/bin/azazel-block.sh
grep -q "/etc/azazel-edge/vector" /var/ossec/etc/ossec.conf
```
