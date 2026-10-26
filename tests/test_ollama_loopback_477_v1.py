"""Edge#477: Ollama (no authentication) is published on loopback only.

Every client is on the same host and uses http://127.0.0.1:11434: the AI
agent (AZAZEL_OLLAMA_ENDPOINT default), PicoClaw (api_base) and the MIO model
adapter. The bundled compose file published 11434 on all interfaces.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "security" / "docker-compose.ollama.yml"


def test_the_ollama_port_is_published_on_loopback_only():
    service = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["ollama"]
    assert "network_mode" not in service  # host networking would bypass the mapping
    assert service["ports"] == ["127.0.0.1:11434:11434"]


def test_every_in_repo_client_uses_the_loopback_endpoint():
    agent = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert 'os.environ.get("AZAZEL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")' in agent
    adapter = (ROOT / "py" / "azazel_edge" / "mio" / "model_adapter.py").read_text(encoding="utf-8")
    assert "endpoint: str = 'http://127.0.0.1:11434'" in adapter
    picoclaw = (ROOT / "installer" / "internal" / "install_picoclaw.sh").read_text(encoding="utf-8")
    bases = re.findall(r'"api_base": "([^"]+)"', picoclaw)
    assert bases and all(b.startswith("http://127.0.0.1:11434") for b in bases)
    # No installer or unit points a client at another address of this host.
    for path in list((ROOT / "installer").rglob("*.sh")) + list((ROOT / "systemd").glob("*.service")):
        for host in re.findall(r"https?://([^/:\s\"']+):11434", path.read_text(encoding="utf-8")):
            assert host == "127.0.0.1", f"{path}: {host}"
