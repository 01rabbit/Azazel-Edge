"""Explicit test-only SIGTERM flag and genuine API-return completion binding."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal

from azazel_edge.outcome import input_auth, telemetry
from azazel_edge.benchmark.benefit import manifest_digest
from signed_network_phase_recording import _identity, canonical
from signed_network_recording import _clock_anchor, decode_calls_prefix

SCHEMA = "edge-observer-normal-stop-completion/v1"
MAX_RECEIPT_BYTES = 65536
MAX_SIDECAR_BYTES = 4 * 1024 * 1024


def _need(condition, message):
    if not condition:
        raise ValueError(message)


class StopFlag:
    def __init__(self):
        self.requested = False

    def handler(self, signum, frame):
        self.requested = True

    def is_set(self):
        return self.requested


class CapturedControl:
    def __init__(self, config, options):
        self.config, self.options = config, options
        self.flag = StopFlag()
        self.result = None
        self.calls = 0
        self.api_return_anchor = None
        self.restored = False
        self.published = False
        self.identity = _identity()
        self.trust = input_auth.TrustPolicy.from_file(
            Path(config["policy_path"]), role="observer"
        )
        policy_path = Path(options["--policy"])
        policy = json.loads(policy_path.read_bytes())
        source = str(policy_path)
        policy_object = telemetry.OutcomeTelemetryPolicy.from_mapping(
            policy, source_ref=source
        )
        self.policy_context = dict(
            policy_sha256=manifest_digest(policy),
            policy_source_ref=source,
            policy_ref=policy_object.policy_ref,
        )
        self.journal_policy = telemetry.persistence_context(
            policy_object,
            options["--interface"],
            float(options["--sample-interval-seconds"]),
        )

    def run_live(self, original, *args, **kwargs):
        _need(
            self.calls == 0 and "stop_requested" not in kwargs,
            "normal stop wrapper must forward exactly once",
        )
        self.calls += 1
        result = original(*args, **kwargs, stop_requested=self.flag.is_set)
        self.result = result
        self.api_return_anchor = _clock_anchor()
        return result

    def require_result(self):
        from azazel_edge.outcome.input_control_stop import ObserverControlStop

        _need(
            self.calls == 1 and type(self.result) is ObserverControlStop,
            "genuine ObserverControlStop API result required",
        )
        self.result.validate()
        data = self.result.to_dict()
        # Runtime validation proves closure; the test wrapper independently binds scope.
        _need(
            self.flag.is_set() is True and self.api_return_anchor is not None,
            "control request not observed",
        )
        _need(
            data["scope_ref"] == self.trust.data["scope_ref"]
            and data["trust_sha256"] == self.trust.digest,
            "control receipt trust scope differs",
        )
        _need(
            data["journal_boot_id"]
            == self.identity["boot_id"]
            == self.options["--journal-boot-id"],
            "control receipt boot differs",
        )
        _need(
            data["journal_policy_sha256"]
            == hashlib.sha256(self.journal_policy.encode()).hexdigest(),
            "control receipt journal policy differs",
        )
        return data


@contextmanager
def capture_control(config, options):
    captured = CapturedControl(config, options)
    original = telemetry.run_live
    previous = signal.getsignal(signal.SIGTERM)

    def forward(*args, **kwargs):
        return captured.run_live(original, *args, **kwargs)

    signal.signal(signal.SIGTERM, captured.flag.handler)
    telemetry.run_live = forward
    try:
        yield captured
    finally:
        telemetry.run_live = original
        signal.signal(signal.SIGTERM, previous)
        captured.restored = True


def _sidecar(path, maximum=MAX_SIDECAR_BYTES):
    raw, info = input_auth.read_regular(
        Path(path), owner=os.geteuid(), mode=0o600, max_bytes=maximum
    )
    return raw, dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))


def publish_completion(captured, *, phase_recorder=None):
    """Publish only after handler restoration and every required sidecar close."""
    _need(
        captured.restored and not captured.published,
        "completion already published or handler unrestored",
    )
    body = captured.require_result()
    identity = _identity()
    _need(
        all(
            identity[key] == captured.identity[key]
            for key in ("pid", "start_ticks", "boot_id")
        ),
        "observer incarnation changed",
    )
    config = captured.config
    sidecars = dict(phase=None, calls=None, context=None)
    if config["normal_stop"]["profile"] == "phase_and_clock":
        _need(
            phase_recorder is not None
            and phase_recorder.closed
            and phase_recorder.fd is None
            and not phase_recorder.incomplete,
            "phase recorder close incomplete",
        )
        phase_raw, sidecars["phase"] = _sidecar(config["traces"]["observer"])
        phase_end = json.loads(phase_raw.splitlines()[-1])
        _need(
            phase_end["kind"] == "end" and phase_end["data"]["normal_return"] is True,
            "normal phase footer absent",
        )
        calls_raw, sidecars["calls"] = _sidecar(config["clock"]["calls_path"])
        calls = decode_calls_prefix(calls_raw)
        _need(
            calls["closed"] and not calls["partial_tail"],
            "callback recording close incomplete",
        )
        context_raw, sidecars["context"] = _sidecar(
            config["clock"]["context_path"], 16384
        )
        contexts = context_raw.splitlines(keepends=True)
        _need(len(contexts) == 2, "clock context end absent")
        end = json.loads(contexts[-1])
        _need(
            end["kind"] == "end" and end["data"]["normal_return"] is True,
            "clock context normal end absent",
        )
    receipt = dict(
        schema_version=SCHEMA,
        metadata=dict(config["metadata"], role="observer"),
        identity=identity,
        policy_context=captured.policy_context,
        control_stop=body,
        api_return_anchor=captured.api_return_anchor,
        sidecars=sidecars,
        completion_anchor=_clock_anchor(),
    )
    raw = canonical(receipt)
    _need(len(raw) <= MAX_RECEIPT_BYTES, "completion receipt byte bound")
    fd = os.open(
        config["normal_stop"]["receipt_path"],
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _need(count > 0, "completion receipt write stopped")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    captured.published = True
    return receipt
