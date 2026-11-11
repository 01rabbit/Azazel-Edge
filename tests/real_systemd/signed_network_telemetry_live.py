"""Fixed manual live caller; owns only its observer unit/client and three pipes.

Not a scope/trial runner. Outer Root owns witness/core/namespaces, durable
input_ready observation and native stop. Public JSON never authenticates itself.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time

import signed_network_telemetry_initialize as init
from azazel_edge.outcome.input_witness import validate_state

lab, g, role, material, proof = init.lab, init.g, init.role, init.material, init.proof


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _initialized(value, binding):
    """Structural continuity only; caller supplies the direct current init return."""
    lab.need(
        type(value) is dict
        and set(value)
        == {
            "initialization",
            "binding",
            "proof",
            "authorizes_transition",
            "experiment",
            "production_admission",
        }
        and all(
            value[k] is False
            for k in ("authorizes_transition", "experiment", "production_admission")
        )
        and _same(value["binding"], binding),
        "current successful initializer binding required",
    )
    result, ready = value["initialization"], value["proof"]["ready"]
    proof.legacy.validate_role_identity(result["identity"])
    lab.need(
        set(result)
        == {
            "initialized_empty",
            "identity",
            "kernel_boot_id",
            "boot_ref",
            "policy_sha256",
            "policy_file_sha256",
        }
        and result["initialized_empty"] is True
        and ready["mode"] == "initialize"
        and ready["role"] == role.ROLE
        and _same(result["identity"], ready["identity"])
        and result["kernel_boot_id"] == binding["kernel_boot_id"]
        and result["boot_ref"] == init.plan.n.boot_reference(binding["kernel_boot_id"])
        and all(
            result[k] == binding[k] for k in ("policy_sha256", "policy_file_sha256")
        ),
        "unchanged genuine empty initialization required",
    )


def _position(value):
    lab.need(
        type(value) is dict
        and set(value) == {"offset", "sha256"}
        and type(value["offset"]) is int
        and 0 <= value["offset"] < 2**64
        and type(value["sha256"]) is str
        and re.fullmatch("[0-9a-f]{64}", value["sha256"]),
        "typed source position required",
    )
    return value["offset"]


def _terminal(raw, verified, binding):
    """Validate the pinned worker's result shape/bindings, not reauthenticate JSON."""
    value = init.plan.strict(raw)
    lab.need(
        type(value) is dict
        and set(value)
        == {"context", "end_clock_anchor", "terminal", "witness_state", "scope"}
        and value["scope"]
        == "real_observer_calls_and_terminal_control_not_measurement_success",
        "fixed live worker result required",
    )
    context, terminal = value["context"], value["terminal"]
    lab.need(
        type(context) is dict
        and set(context)
        == {
            "identity",
            "kernel_boot_id",
            "boot_ref",
            "signed_boot_ref",
            "scope_ref",
            "registration_sha256",
            "policy_sha256",
            "policy_file_sha256",
            "source_start_position",
            "clock_anchor",
        }
        and _same(context["identity"], verified["ready"]["identity"])
        and context["kernel_boot_id"] == binding["kernel_boot_id"]
        and context["boot_ref"] == init.plan.n.boot_reference(binding["kernel_boot_id"])
        and context["signed_boot_ref"] == binding["kernel_boot_id"].replace("-", "")
        and all(
            context[k] == binding[k] for k in ("policy_sha256", "policy_file_sha256")
        )
        and context["scope_ref"] == binding["public_auth"]["scope_ref"]
        and context["registration_sha256"]
        == binding["public_auth"]["origin_registration_sha256"],
        "live context differs from current Root binding",
    )
    fields = {
        "disposition",
        "cursor_disposition",
        "cursor_missed",
        "registration_sha256",
        "session_ref",
        "native_seq",
        "source_position_before",
        "source_position_after",
        "signed_wire_sha256",
        "signed_wire_bytes",
        "decoded_record_sha256",
        "decoded_record_bytes",
        "pending_windows_lost",
        "measurement_completed",
        "resume_authorized",
    }
    lab.need(
        type(terminal) is dict
        and set(terminal) == fields
        and terminal["disposition"] == "verified_terminal_control_stop"
        and terminal["cursor_disposition"] == "control_not_observed"
        and terminal["cursor_missed"] is True
        and terminal["measurement_completed"] is False
        and terminal["resume_authorized"] is False
        and terminal["registration_sha256"] == context["registration_sha256"]
        and type(terminal["session_ref"]) is str
        and re.fullmatch("[0-9a-f]{32}", terminal["session_ref"]),
        "typed terminal CONTROL result required",
    )
    for key in (
        "native_seq",
        "signed_wire_bytes",
        "decoded_record_bytes",
        "pending_windows_lost",
    ):
        lab.need(
            type(terminal[key]) is int
            and (0 if key == "pending_windows_lost" else 1) <= terminal[key] < 2**64,
            "typed terminal bound required",
        )
    for key in ("signed_wire_sha256", "decoded_record_sha256"):
        lab.need(
            type(terminal[key]) is str and re.fullmatch("[0-9a-f]{64}", terminal[key]),
            "terminal digest required",
        )
    before, after = (
        _position(terminal[k])
        for k in ("source_position_before", "source_position_after")
    )
    lab.need(
        _position(context["source_start_position"]) <= before
        and after - before == terminal["signed_wire_bytes"],
        "terminal source positions differ",
    )
    state = validate_state(value["witness_state"])
    lab.need(
        state["source_size"] == after
        and state["source_sha256"] == terminal["source_position_after"]["sha256"],
        "worker witness tip differs",
    )
    for anchor in (context["clock_anchor"], value["end_clock_anchor"]):
        lab.need(
            type(anchor) is dict
            and set(anchor) == {"monotonic_before_ns", "epoch_ns", "monotonic_after_ns"}
            and all(type(v) is int and 0 <= v < 2**63 for v in anchor.values())
            and anchor["monotonic_before_ns"] <= anchor["monotonic_after_ns"],
            "actual worker anchor shape required",
        )
    lab.need(
        value["end_clock_anchor"]["monotonic_before_ns"]
        >= context["clock_anchor"]["monotonic_after_ns"],
        "worker anchors out of order",
    )
    return value


class LiveSession:
    """Status-only public view; helper exclusively owns pipes/wait/drain/reap."""

    def __init__(self, process):
        self._process, self._result = process, None

    @property
    def pid(self):
        return self._process.pid

    @property
    def returncode(self):
        return self._process.returncode

    def poll(self):
        return self._process.poll()

    @property
    def result(self):
        return self._result  # None until normal completion AND clean teardown.


@contextmanager
def live(
    output,
    *,
    abi_sha256,
    interpreter_sha256,
    source_sha256,
    expected_sources,
    namespace_fd,
    namespace_identity,
    transport_context,
    initialization,
):
    """One current live role, no manifest/workload/Scope provisioning or retry.

    initialization is the direct successful return from this Root controller's
    current init call, never imported JSON authority. The outer body must only
    poll status, await ACTUAL durable input_ready independently, and stop native
    core naturally. It must not wait/read/communicate with the owned client.
    Outer witness/core/namespace teardown is always the caller's responsibility.
    """
    g.guard()
    material.pin(source_sha256)
    current = material.verify_current(
        abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
    )
    lab.need(
        type(expected_sources) is dict
        and expected_sources == current["source_sha256"]
        and current["source_sha256"][str(Path(role.SOURCE).relative_to(material.SRC))]
        == source_sha256,
        "independently frozen current source pins differ",
    )
    output = Path(output)
    proof.p._output(output)
    namespace = init._namespace(namespace_fd, namespace_identity)
    unit = role.OBSERVER_UNIT
    init.prelaunch_unit_material("live", output)
    lab.need(
        init.scope._known_collected(init.scope._state(unit))
        and lab.cg.group_empty("/system.slice/" + unit, (unit,)),
        "existing live role refused",
    )
    kernel = g.boot()
    lab.boot_reference(kernel)
    binding, _ = init._current_binding(
        current=current,
        namespace=namespace,
        source_sha256=source_sha256,
        kernel=kernel,
        output=output,
        phase="live-initial",
        transport_context=transport_context,
    )
    _initialized(initialization, binding)
    argv = init.observer.role_argv("live", telemetry_lab_v2=True)
    lab.save_json(output / "live-intent.json", dict(argv=argv, binding=binding))
    process, error, session, candidate = None, None, None, None
    tracked = {unit: []}
    try:
        deadline = time.monotonic() + role.RUNTIME_SECONDS
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        verified = proof.collect_pre_api(
            "live",
            process,
            expected_namespace=namespace,
            kernel_boot_id=kernel,
            source_sha256=source_sha256,
            output=output,
        )
        lab.need(
            type(verified) is dict
            and set(verified) == {"ready", "effective", "actor", "metadata"}
            and all(type(v) is dict and v for v in verified.values()),
            "complete verified Root bundle required",
        )
        tracked[unit].append(verified["actor"]["evidence"]["before"])

        def unchanged(phase):
            fresh = material.verify_current(
                abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
            )
            sampled, _ = init._current_binding(
                current=fresh,
                namespace=init._namespace(namespace_fd, namespace_identity),
                source_sha256=source_sha256,
                kernel=g.boot(),
                output=output,
                phase="live-" + phase,
                transport_context=transport_context,
            )
            lab.save_json(output / ("live-binding-" + phase + ".json"), sampled)
            lab.need(
                _same(sampled, binding),
                "current live public/config/material binding changed",
            )

        unchanged("before-go")
        lab.save_json(
            output / "live-verified-bundle.json",
            dict(
                proof=verified,
                binding=binding,
                binding_sha256=init.plan.manifest_digest(binding),
            ),
        )
        # save_json fsyncs file data; persist its directory entry before GO.
        directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        lab.need(select.select([], [process.stdin], [], 2)[1], "live GO write deadline")
        lab.need(
            os.write(process.stdin.fileno(), role.GO) == len(role.GO),
            "live short GO write",
        )
        process.stdin.close()
        session = LiveSession(process)
        yield session
        raw = init._drain(process, output, deadline, prefix="live-terminal")
        lab.need(
            process.returncode == 0 and raw["stderr"] == b"",
            "actual live worker failed",
        )
        terminal = _terminal(raw["stdout"], verified, binding)
        unchanged("after-terminal")
        candidate = dict(
            terminal=terminal,
            binding=binding,
            proof=verified,
            authorizes_transition=False,
            experiment=False,
            production_admission=False,
        )
    except BaseException as exc:
        error = exc
    finally:

        def attempt(name, operation):
            nonlocal error
            try:
                return operation()
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note(name + ":" + type(exc).__name__)

        cleanup = attempt(
            "fixed live stop/proof", lambda: lab.cleanup((unit,), tracked)
        )
        attempt(
            "cleanup receipt",
            lambda: lab.save_json(output / "live-cleanup.json", cleanup),
        )
        attempt(
            "cleanup proof",
            lambda: lab.need(
                type(cleanup) is dict and cleanup.get("errors") == [],
                "live cleanup incomplete",
            ),
        )
        if process is not None:
            attempt(
                "owned residual streams",
                lambda: init._drain(
                    process, output, time.monotonic() + 2, prefix="live-cleanup-streams"
                ),
            )
            reaped = attempt("owned client reap", lambda: init._reap_client(process))
            attempt(
                "reap receipt",
                lambda: lab.save_json(output / "live-client-reap.json", reaped),
            )
            attempt(
                "reap proof",
                lambda: lab.need(
                    type(reaped) is dict
                    and reaped.get("reaped") is True
                    and reaped.get("forced") is False
                    and reaped.get("errors") == [],
                    "live client not cleanly reaped",
                ),
            )
            for stream in (process.stdin, process.stdout, process.stderr):
                attempt("owned pipe close", stream.close)
    if error is not None:
        raise error
    lab.save_json(output / "live-result.json", candidate)
    session._result = candidate
