from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from azazel_edge.ai_governance import AIGovernance


class MioModelError(RuntimeError):
    pass


class MioModelBlocked(MioModelError):
    pass


class MioModelUnavailable(MioModelError):
    pass


class StructuredTransport(Protocol):
    last_model: str

    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]: ...


def _endpoint_kind(endpoint: str, *, allow_private_network: bool) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        return 'rejected'
    host = parsed.hostname.lower()
    if host == 'localhost':
        return 'loopback'
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # No arbitrary DNS names in the M.I.O. model path. This deliberately
        # prevents an "allowed host" knob from becoming accidental cloud fallback.
        return 'rejected'
    if address.is_loopback:
        return 'loopback'
    if allow_private_network and address.is_private and not address.is_link_local:
        return 'private_lan'
    return 'rejected'


@dataclass
class OllamaStructuredTransport:
    """Small, bounded Ollama JSON transport for local/on-prem inference.

    Default endpoint policy is loopback-only. A private LAN endpoint requires
    explicit opt-in, HTTPS, and a bearer token (for an authenticated local
    reverse proxy or equivalent). Public endpoints and arbitrary DNS names are
    rejected so cloud fallback cannot appear accidentally.
    """

    endpoint: str = 'http://127.0.0.1:11434'
    models: Sequence[str] = ('qwen3.5:2b', 'qwen3.5:0.8b')
    timeout_seconds: float = 20.0
    max_response_chars: int = 12000
    num_ctx: int = 2048
    num_predict: int = 768
    num_thread: int = 2
    allow_private_network: bool = False
    bearer_token: str = ''
    last_model: str = ''

    def __post_init__(self) -> None:
        self.endpoint = self.endpoint.rstrip('/')
        self.timeout_seconds = max(0.2, min(float(self.timeout_seconds), 120.0))
        self.max_response_chars = max(512, min(int(self.max_response_chars), 100_000))
        self.num_ctx = max(256, min(int(self.num_ctx), 32768))
        self.num_predict = max(32, min(int(self.num_predict), 4096))
        self.num_thread = max(1, min(int(self.num_thread), 32))
        self.models = tuple(str(model).strip()[:128] for model in self.models if str(model).strip())
        self.bearer_token = str(self.bearer_token or '')
        if not self.models:
            raise ValueError('mio_no_models_configured')
        kind = _endpoint_kind(self.endpoint, allow_private_network=bool(self.allow_private_network))
        if kind == 'rejected':
            raise ValueError('mio_endpoint_not_local_or_allowed_private')
        if kind == 'private_lan':
            parsed = urlparse(self.endpoint)
            if parsed.scheme != 'https':
                raise ValueError('mio_private_endpoint_requires_https')
            if not self.bearer_token:
                raise ValueError('mio_private_endpoint_requires_auth')

    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]:
        if not isinstance(prompt, str) or not prompt:
            raise MioModelError('mio_prompt_empty')
        failures = 0
        for model in self.models:
            try:
                result = self._invoke_model(model=model, task=task, prompt=prompt)
            except MioModelUnavailable:
                failures += 1
                continue
            self.last_model = model
            return result
        self.last_model = ''
        raise MioModelUnavailable(f'mio_all_local_models_unavailable:{failures}')

    def _invoke_model(self, *, model: str, task: str, prompt: str) -> Mapping[str, Any]:
        body = {
            'model': model,
            'prompt': prompt,
            'stream': False,
            'format': 'json',
            'options': {
                'num_ctx': self.num_ctx,
                'num_predict': self.num_predict,
                'num_thread': self.num_thread,
                'temperature': 0.1,
            },
        }
        data = json.dumps(body, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'azazel-edge-mio-shadow/1'}
        if self.bearer_token:
            headers['Authorization'] = 'Bearer ' + self.bearer_token
        request = urllib.request.Request(
            self.endpoint + '/api/generate',
            data=data,
            headers=headers,
            method='POST',
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw_bytes = response.read(self.max_response_chars + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MioModelUnavailable(f'mio_model_transport_error:{type(exc).__name__}') from None
        if len(raw_bytes) > self.max_response_chars:
            raise MioModelUnavailable('mio_model_response_too_large')
        try:
            envelope = json.loads(raw_bytes.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MioModelUnavailable('mio_model_envelope_invalid') from None
        if not isinstance(envelope, Mapping):
            raise MioModelUnavailable('mio_model_envelope_not_object')
        response_text = envelope.get('response')
        if not isinstance(response_text, str) or not response_text.strip():
            raise MioModelUnavailable('mio_model_response_empty')
        if len(response_text) > self.max_response_chars:
            raise MioModelUnavailable('mio_model_payload_too_large')
        try:
            payload = json.loads(response_text)
        except json.JSONDecodeError:
            raise MioModelUnavailable('mio_model_payload_not_json') from None
        if not isinstance(payload, Mapping):
            raise MioModelUnavailable('mio_model_payload_not_object')
        return dict(payload)


class GovernedMioModelAdapter:
    """Route structured M.I.O. model calls through the existing AI gate.

    The compiled reasoning prompt is not written to the governance audit. Only a
    bounded task identifier and prompt digest are logged. Domain-specific output
    remains subject to the M.I.O. deterministic grounding validator in the
    reasoning loop.
    """

    def __init__(
        self,
        *,
        governance: AIGovernance,
        transport: StructuredTransport,
        trace_id: str,
        source: str,
        risk_band: str,
    ):
        self.governance = governance
        self.transport = transport
        self.trace_id = str(trace_id or '')[:96]
        self.source = str(source or '')[:64]
        self.risk_band = str(risk_band or '')[:32]

    def __call__(self, task: str, prompt: str) -> Mapping[str, Any]:
        task_name = str(task or '')[:64]
        prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:24]
        context = {
            'trace_id': self.trace_id,
            'source': self.source,
            'intent': 'candidate',
            'risk_band': self.risk_band,
        }
        audit_payload = {
            'trace_id': self.trace_id,
            'source': self.source,
            'intent': 'candidate',
            'summary': f'mio_shadow task={task_name} prompt_sha256={prompt_hash}',
            'candidate_scope': f'mio:{task_name}',
        }
        allowed, reason, _sanitized = self.governance.authorize(context, audit_payload)
        if not allowed:
            raise MioModelBlocked(f'mio_governance_blocked:{reason}')

        try:
            output = self.transport(task_name, prompt)
        except Exception as exc:
            self.governance.record_structured_result(
                trace_id=self.trace_id,
                source=self.source,
                candidate_scope=f'mio:{task_name}',
                decision='fallback',
                metadata={'task': task_name, 'model': getattr(self.transport, 'last_model', ''), 'error': type(exc).__name__},
            )
            if isinstance(exc, MioModelError):
                raise
            raise MioModelUnavailable(f'mio_transport_failed:{type(exc).__name__}') from None

        if not isinstance(output, Mapping):
            self.governance.record_structured_result(
                trace_id=self.trace_id,
                source=self.source,
                candidate_scope=f'mio:{task_name}',
                decision='rejected',
                metadata={'task': task_name, 'model': getattr(self.transport, 'last_model', ''), 'error': 'not_mapping'},
            )
            raise MioModelUnavailable('mio_structured_output_not_mapping')

        response_chars = len(json.dumps(dict(output), separators=(',', ':'), ensure_ascii=True))
        self.governance.record_structured_result(
            trace_id=self.trace_id,
            source=self.source,
            candidate_scope=f'mio:{task_name}',
            decision='adopted_pending_grounding',
            metadata={
                'task': task_name,
                'model': getattr(self.transport, 'last_model', ''),
                'response_chars': response_chars,
            },
        )
        return dict(output)
