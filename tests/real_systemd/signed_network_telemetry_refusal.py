"""One fresh manual negative connection case; no core/native/traffic or trial.

External Root source/profile staging and a NEW VM/scope are mandatory. This
controller owns only its newly provisioned fixed actors and NamespaceSetup.
"""

import hashlib
import os
from pathlib import Path
import secrets
import stat

import signed_network_telemetry_commission as main
import signed_network_telemetry_fault as fault

setup, lab, g, plan, material = main.setup, main.lab, main.g, main.plan, main.material


def refuse_synthetic_input(
    output,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Actual invalid-signature refusal plus cleanup only, never an experiment."""
    baseline = setup.preflight(
        output,
        source_commit=source_commit,
        archive_sha256=archive_sha256,
        core_sha256=core_sha256,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
    )
    output = Path(output)
    namespaces = main.NamespaceSetup(output, baseline)
    owned, tracked, initialized, failure, evidence = set(), {}, None, None, None
    original = (g.write, g.prepare, g.observer, dict(g.ENV), plan.p.a.NATIVE)
    cleanup, namespace_cleanup = None, None
    try:
        namespaces.prepare()
        fd, pair = namespaces.edge()
        sources = baseline["material"]["source_sha256"]
        observer_sha = sources[str(Path(setup.role.SOURCE).relative_to(material.SRC))]
        args = dict(
            abi_sha256=abi_sha256,
            interpreter_sha256=interpreter_sha256,
            source_sha256=observer_sha,
            expected_sources=sources,
            namespace_fd=fd,
            namespace_identity=pair,
        )
        for name in ("initialize", "live", "fault"):
            material.preflight.old.private_output(output / name)

        def initialize(create=False):
            nonlocal initialized
            lab.need(
                create is True and initialized is None,
                "only current genuine fresh init",
            )
            main._base_created(output)
            initialized = main.initializer.initialize(output / "initialize", **args)
            owned.add(setup.role.INITIALIZER_UNIT)
            tracked[setup.role.INITIALIZER_UNIT] = [
                initialized["proof"]["actor"]["evidence"]["before"]
            ]
            return initialized

        def created(path, data):
            info = os.stat(path, follow_symlinks=False)
            lab.need(
                info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "current exclusive unit creation ownership required",
            )
            owned.add(path.name)
            lab.save_json(
                output / ("created-" + path.name + ".json"),
                dict(
                    device=info.st_dev,
                    inode=info.st_ino,
                    sha256=hashlib.sha256(
                        data if type(data) is bytes else data.encode()
                    ).hexdigest(),
                ),
            )

        main._configure(initialize, created)
        lab.need(not os.path.lexists(g.BASE), "new scope only")
        lab.save_json(
            output / "auth-scope-create-intent.json",
            dict(
                creator="current_guest_prepare_lab",
                environment=plan.native_environment("c0"),
                purpose="separate_synthetic_invalid_signature_case",
            ),
        )
        g.prepare_lab()  # Witness first, genuine EMPTY initialization; no core start.
        tracked[g.WITNESS] = [lab.unit_snapshot(g.WITNESS)]
        trust = main.TrustPolicy(
            plan.strict(material._read(g.BUNDLE / "trust.json", 8192))
        )
        main.layout(g.BUNDLE, trust)
        registered = main.registration(trust, g.BUNDLE / "origin.json")
        lab.need(
            registered["schema_version"] == "outcome-live-origin-registration/v4"
            and registered["environment"] == plan.native_environment("c0")
            and registered["binary_sha256"] == core_sha256,
            "registered current C0 context differs",
        )
        namespaces.edge()
        snapshot = fault.capture_init(
            output / "fault", trust=trust, initialization=initialized
        )
        snapshot = fault.inject(
            output / "fault", snapshot=snapshot, session_ref=secrets.token_hex(16)
        )
        namespaces.edge()
        expected_failure = None
        try:
            with main.live(output / "live", initialization=initialized, **args):
                owned.add(setup.role.OBSERVER_UNIT)
                # No input_ready assertion: invalid source must refuse before resume.
                pass
        except BaseException as exc:
            expected_failure = exc
        lab.need(
            expected_failure is not None,
            "synthetic invalid source unexpectedly accepted",
        )
        evidence = fault.classify_refusal(
            output / "fault",
            snapshot=snapshot,
            live_output=output / "live",
            failure=expected_failure,
        )
    except BaseException as exc:
        failure = exc
    finally:
        errors = []

        def attempt(name, operation):
            try:
                return operation()
            except BaseException as exc:
                errors.append((name, type(exc).__name__))

        units = tuple(
            u
            for u in (
                setup.role.INITIALIZER_UNIT,
                setup.role.OBSERVER_UNIT,
                g.UNIT,
                g.WITNESS,
            )
            if u in owned
        )
        cleanup = attempt(
            "owned actors",
            lambda: lab.cleanup(units, {u: tracked.get(u, []) for u in units}),
        )
        attempt(
            "actor receipt",
            lambda: lab.save_json(output / "refusal-actor-cleanup.json", cleanup),
        )
        attempt(
            "actor proof",
            lambda: lab.need(
                type(cleanup) is dict and cleanup.get("errors") == [],
                "outer actor cleanup incomplete",
            ),
        )
        if errors:
            namespaces.failed = True
        namespace_cleanup = attempt("namespace/marker close", namespaces.close)
        attempt(
            "namespace proof",
            lambda: lab.need(
                type(namespace_cleanup) is dict
                and namespace_cleanup.get("cleanup_verified") is True
                and namespace_cleanup.get("errors") == [],
                "outer namespace cleanup incomplete",
            ),
        )
        g.write, g.prepare, g.observer, environment, plan.p.a.NATIVE = original
        g.ENV.clear()
        g.ENV.update(environment)
        if errors:
            if failure is None:
                failure = RuntimeError("negative cleanup incomplete: " + str(errors))
            else:
                failure.add_note("negative cleanup: " + str(errors))
    if failure is not None:
        raise failure
    result = dict(
        status="synthetic_input_refusal_complete",
        scope="single_source_signature_refusal_with_outer_cleanup_only",
        evidence=evidence,
        outer_actor_cleanup=cleanup,
        namespace_cleanup=namespace_cleanup,
        pins=baseline["pins"],
        kernel_boot_id=baseline["kernel_boot_id"],
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
        measurement_completed=False,
    )
    lab.save_json(output / "refusal-result.json", result)
    return result
