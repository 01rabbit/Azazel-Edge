# ruff: noqa: E402
"""Pinned v3 test bootstrap; original enforcing registrations are always refused."""

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sys

if __name__ == "__main__":
    sys.dont_write_bytecode = True

from azazel_edge.outcome import input_auth, input_live, telemetry
from signed_network_phase_recording import (
    ModuleProxy, PhaseRecording, record_observer, record_receiver,
)

SCHEMA = "edge-phase-timing-config/v1"
SCHEMA_V2 = "edge-phase-timing-config/v2"


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def refuse_profiles(value):
    """Never strip profile declarations or instrument an enforcing registration."""
    if type(value) is dict:
        for key, child in value.items():
            _need(type(key) is str and "profile" not in key.lower(), "declared profile refused")
            refuse_profiles(child)
    elif type(value) is list:
        for child in value:
            refuse_profiles(child)


def _root_bytes(path, maximum=1024 * 1024, mode=0o444):
    return input_auth.read_regular(Path(path), owner=0, mode=mode, max_bytes=maximum)[0]


def load_config(path, expected_sha256):
    _need(type(expected_sha256) is str and re.fullmatch("[0-9a-f]{64}", expected_sha256), "config pin")
    raw = _root_bytes(path, 65536)
    _need(_digest(raw) == expected_sha256, "config pin differs")
    config = json.loads(raw)
    _need(input_auth._json(config) + b"\n" == raw, "canonical config plus LF")
    _need(type(config) is dict and config.get("schema_version") in (SCHEMA, SCHEMA_V2), "config schema")
    version_two = config["schema_version"] == SCHEMA_V2
    fields = {"schema_version", "metadata", "registration_path", "policy_path", "traces",
              "worker_path", "worker_sha256"}
    _need(set(config) == fields | ({"clock"} if version_two else set()), "config fields")
    metadata = config["metadata"]
    _need(type(metadata) is dict and set(metadata) == {
        "run_id", "arm", "input_sha256", "code_sha256", "core_sha256", "interpreter_sha256",
    }, "metadata fields")
    _need(metadata["arm"] in ("instrumented_off", "instrumented_on", "instrumented_faulted"), "instrumented arm required")
    _need(type(metadata["run_id"]) is str and re.fullmatch("[A-Za-z0-9_-]{1,128}", metadata["run_id"]), "run id")
    for key in ("input_sha256", "code_sha256", "core_sha256", "interpreter_sha256"):
        _need(type(metadata[key]) is str and re.fullmatch("[0-9a-f]{64}", metadata[key]), "metadata pin")
    _need(type(config["traces"]) is dict and set(config["traces"]) == {"signer", "observer", "witness"}, "trace roles")
    for value in (*config["traces"].values(), config["registration_path"], config["policy_path"], config["worker_path"]):
        _need(type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts, "physical config path")
    _need(len(set(config["traces"].values())) == 3, "trace paths alias")
    worker = _root_bytes(config["worker_path"])
    helper_path = Path(config["worker_path"]).with_name("signed_network_phase_recording.py")
    helper = _root_bytes(helper_path)
    _need(Path(config["worker_path"]) == Path(__file__).absolute(), "worker path differs")
    _need(_digest(worker) == config["worker_sha256"], "worker pin differs")
    bootstrap = worker + b"\0" + helper
    if version_two:
        clock = config["clock"]
        _need(type(clock) is dict and set(clock) == {
            "helper_path", "helper_sha256", "recording_path", "recording_sha256",
            "calls_path", "context_path",
        }, "clock config fields")
        paths = [*config["traces"].values()]
        for key in ("calls_path", "context_path", "helper_path", "recording_path"):
            value = clock[key]
            _need(type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts,
                  "physical clock path")
            paths.append(value)
        _need(len(set(paths)) == len(paths), "clock paths alias")
        for prefix, name in (("helper", "signed_network_load_clock.py"),
                             ("recording", "signed_network_recording.py")):
            _need(Path(clock[prefix + "_path"]) == Path(config["worker_path"]).with_name(name),
                  "adjacent clock helper required")
            original = _root_bytes(clock[prefix + "_path"])
            _need(_digest(original) == clock[prefix + "_sha256"], "clock helper pin differs")
            bootstrap += b"\0" + original
    _need(_digest(bootstrap) == metadata["code_sha256"], "bootstrap pin differs")
    _need(_digest(Path(sys.executable).resolve().read_bytes()) == metadata["interpreter_sha256"], "interpreter pin differs")
    registration = json.loads(input_auth.read_regular(Path(config["registration_path"]), owner=0, max_bytes=65536)[0])
    refuse_profiles(registration)
    _need(registration.get("binary_sha256") == metadata["core_sha256"], "core pin differs")
    return config


def _options(argv, names):
    _need(type(argv) is list and len(argv) == 2 * len(names), "original argv shape")
    _need(argv[::2] == names, "original argv order")
    _need(all(type(v) is str and v for v in argv), "original argv type")
    return dict(zip(argv[::2], argv[1::2]))


def validate_input_args(argv, config, *, receiver=False, policy=None):
    names = ["--policy", "--registration", "--private-key", "--boot-ref"]
    if receiver:
        names += ["--receive-fd", "--session-ref"]
    options = _options(argv, names)
    _need(options["--policy"] == config["policy_path"] and options["--registration"] == config["registration_path"], "original public paths differ")
    # Read the exact original trust policy, preserving its parser and registration checks.
    if policy is None:
        policy = input_auth.TrustPolicy.from_file(Path(config["policy_path"]), role="producer" if receiver else "witness")
    registration = input_live.registration(policy, Path(config["registration_path"]))
    refuse_profiles(registration)
    if receiver:
        _need(re.fullmatch("[0-9]+", options["--receive-fd"]) and int(options["--receive-fd"]) >= 0, "receiver FD")
        _need(re.fullmatch("[0-9a-f]{32}", options["--session-ref"]), "receiver session")
    return options, policy


@contextmanager
def launcher_receiver_proxy(config, config_path, config_sha256):
    """Change only the exact producer child entry; the native Popen is untouched."""
    original = input_live.subprocess
    used = False
    policy = input_auth.TrustPolicy.from_file(Path(config["policy_path"]), role="witness")
    registration = input_live.registration(policy, Path(config["registration_path"]))
    refuse_profiles(registration)
    uid = policy.data["producer_uid"]

    def popen(argv, *args, **kwargs):
        nonlocal used
        if type(argv) is list and len(argv) >= 3 and argv[1:3] == ["-m", "azazel_edge.outcome.input_live"]:
            _need(not used and not args, "repeated or positional receiver Popen")
            _need(argv[0] == sys.executable, "receiver interpreter differs")
            options, _ = validate_input_args(argv[3:], config, receiver=True, policy=policy)
            fd = int(options["--receive-fd"])
            expected = dict(pass_fds=(fd,), stdin=original.DEVNULL, stdout=original.PIPE,
                            user=uid, group=uid, extra_groups=[], cwd="/",
                            env={"PATH": "/nonexistent", "PYTHONPATH": str(Path(input_live.__file__).resolve().parents[2])},
                            close_fds=True)
            _need(kwargs == expected, "receiver Popen options differ")
            used = True
            argv = [argv[0], config["worker_path"], "--role", "receiver", "--config", str(config_path),
                    "--config-sha256", config_sha256, "--", *argv[3:]]
        elif type(argv) is list and "--receive-fd" in argv:
            raise ValueError("unknown receiver Popen refused")
        return original.Popen(argv, *args, **kwargs)

    input_live.subprocess = ModuleProxy(original, Popen=popen)
    try:
        yield
    finally:
        input_live.subprocess = original


def _observer_args(argv, config):
    expected_names = ["--input", "--output", "--policy", "--interface", "--poll-seconds",
                      "--sample-interval-seconds", "--journal-directory", "--journal-scope",
                      "--journal-boot-id", "--journal-max-bytes"]
    _need(len(argv) == 23 and argv[20] == "--journal-resume-input" and argv[21] == "--input-auth-policy", "observer argv shape")
    values = _options(argv[:20], expected_names)
    _need(argv[22] == config["policy_path"], "observer trust differs")
    _need(values["--interface"] == "lo" and values["--poll-seconds"] == values["--sample-interval-seconds"] == "0.05", "observer workload differs")
    if config["schema_version"] == SCHEMA_V2:
        from azazel_edge.outcome.journal import NAME
        reserved = {Path(values[key]) for key in ("--input", "--output", "--policy")}
        reserved.update((Path(config["policy_path"]), Path(config["registration_path"]),
                         Path(values["--journal-directory"]) / NAME))
        for key in ("calls_path", "context_path"):
            target = Path(config["clock"][key])
            _need(target.parent == Path(values["--journal-directory"]),
                  "clock recording must use existing observer directory")
            _need(target not in reserved, "clock output aliases original evidence")
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("launcher", "receiver", "observer"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("original", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    original = args.original
    _need(original and original[0] == "--", "explicit original argv delimiter")
    original = original[1:]
    config = load_config(args.config, args.config_sha256)
    if args.role == "launcher":
        validate_input_args(original, config)
        with launcher_receiver_proxy(config, args.config, args.config_sha256):
            return input_live.main(original)
    role = "signer" if args.role == "receiver" else "observer"
    if args.role == "receiver":
        options, _ = validate_input_args(original, config, receiver=True)
    else:
        observer_options = _observer_args(original, config)
    recorder = PhaseRecording(config["traces"][role], metadata=dict(config["metadata"], role=role))
    normal = False
    try:
        context = record_receiver(recorder, int(options["--receive-fd"])) if role == "signer" else record_observer(recorder)
        with context:
            if role == "observer" and config["schema_version"] == SCHEMA_V2:
                # Imported only after load_config pins both adjacent clock modules.
                from signed_network_load_clock import record_observer_clock
                policy_path = Path(observer_options["--policy"])
                policy = json.loads(policy_path.read_bytes())
                with record_observer_clock(
                    config["clock"]["calls_path"], config["clock"]["context_path"],
                    metadata=dict(config["metadata"], role="observer"),
                    policy=policy, policy_source_ref=str(policy_path),
                ):
                    result = telemetry.main(original)
            else:
                result = input_live.main(original) if role == "signer" else telemetry.main(original)
        normal = result == 0
        return result
    finally:
        recorder.close(normal_return=normal)


if __name__ == "__main__":
    raise SystemExit(main())
