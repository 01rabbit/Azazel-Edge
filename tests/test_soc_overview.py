"""Read-only overview regressions run alongside the Python CI suite."""
from pathlib import Path
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_soc_overview_model():
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    subprocess.run(['node', str(ROOT / 'tests/soc_overview.test.js')], check=True, cwd=ROOT)


def test_overview_render_and_language():
    from azazel_edge_web.app import app
    for lang in ('en', 'ja'):
        response = app.test_client().get('/?lang=' + lang)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'id="socOverview"' in html
        assert 'soc_overview.js' in html
        assert '>overview.title<' not in html
