import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent


@pytest.mark.skipif(shutil.which("make") is None, reason="make not available")
def test_make_demo_runs_and_rejects_tampering():
    result = subprocess.run(
        ["make", "demo"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=180,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "signature valid" in combined
    assert "tampered card correctly rejected" in combined
