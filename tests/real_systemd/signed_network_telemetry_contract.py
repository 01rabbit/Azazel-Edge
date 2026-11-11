"""Fixed optional signed-observer lab metadata; no worker or Root proof runner.

This is not admission, a working CLI, or cryptographic observer-label binding.
The legacy observer and independent precheck contracts are intentionally separate.
"""

ROLE = "telemetry_lab_v2"
PROFILE = "edge400-observer-telemetry-lab"
ALIAS = "/opt/edge400-runtime/bin/edge-observe-telemetry-lab"
SOURCE = "/opt/edge400-src/tests/real_systemd/signed_network_observer.py"
CLI_FLAG = "--telemetry-lab-v2"
READY_KIND = "signed_observer_pre_api_ready"
GO = b"continue-authenticated-api\n"
INITIALIZER_UNIT = "edge400-signed-network-telemetry-initialize.service"
OBSERVER_UNIT = "edge400-signed-network-telemetry-observer.service"
RUNTIME_SECONDS = 40
STOP_SECONDS = 5
NAMESPACE_NAMES = (
    "edge400-provider-edge",
    "edge400-provider-client",
    "edge400-provider-service",
)
NSFS_TARGETS = tuple("/run/netns/" + name for name in NAMESPACE_NAMES)
_UNITS = {"initialize": INITIALIZER_UNIT, "live": OBSERVER_UNIT}


def observer_spec(mode):
    """Return only fresh fixed metadata; later reviewed code must implement it.

    No caller-selected unit/profile/alias/source/namespace and no executable argv.
    Three-stdio-only proof belongs BEFORE authenticated API handles are opened.
    GO never means input_ready, successful isolation, or measurement acceptance.
    """
    if type(mode) is not str or mode not in _UNITS:
        raise ValueError("unknown fixed signed telemetry observer mode")
    return dict(
        role=ROLE,
        mode=mode,
        unit=_UNITS[mode],
        alias=ALIAS,
        source=SOURCE,
        cli_flag=CLI_FLAG,
        namespace=NAMESPACE_NAMES[0],
        nsfs_targets=list(NSFS_TARGETS),
        protocol=dict(ready_kind=READY_KIND, go_ascii=GO.decode("ascii")),
        properties=dict(
            User="edge400-observer",
            Group="edge400-observer",
            AppArmorProfile=PROFILE,
            CapabilityBoundingSet="",
            AmbientCapabilities="",
            NoNewPrivileges="yes",
            RestrictAddressFamilies="AF_UNIX",
            Restart="no",
            DefaultDependencies="no",
            RuntimeMaxSec=str(RUNTIME_SECONDS),
            TimeoutStopSec=str(STOP_SECONDS),
            ProtectProc="ptraceable",
            ProcSubset="all",
            MountAPIVFS="yes",
            NetworkNamespacePath="/run/netns/" + NAMESPACE_NAMES[0],
        ),
    )
