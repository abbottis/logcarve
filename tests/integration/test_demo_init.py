"""Temp-export init regression (T10): fresh clones have no artifacts/ tree.

Copies only the demo scripts plus the synthetic fixture into a temporary
directory (no artifacts/, no repo state) and runs init.sh there: it must
create the protected secrets exclusively, stay idempotent, keep 0700/0600
permissions, and refuse symlinked parents or secret paths. No Docker, no
network, synthetic data only.
"""

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"


def _stage_export(tmp_path):
    export = tmp_path / "export"
    (export / "scripts" / "demo").mkdir(parents=True)
    for name in ("lib.sh", "init.sh", "start.sh", "stop.sh", "reset.sh", "seed.sh", "health.sh"):
        shutil.copy(ROOT / "scripts" / "demo" / name, export / "scripts" / "demo" / name)
    fixture_dir = export / "tests" / "fixtures" / "combined"
    fixture_dir.mkdir(parents=True)
    shutil.copy(FIXTURE, fixture_dir / "t8_smoke.txt")
    assert not (export / "artifacts").exists()
    return export


def _run_init(export):
    return subprocess.run(
        ["sh", str(export / "scripts" / "demo" / "init.sh")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_fresh_export_init_creates_protected_secrets(tmp_path):
    export = _stage_export(tmp_path)
    result = _run_init(export)
    assert result.returncode == 0, result.stderr
    secret_dir = export / "artifacts" / "local-demo-secrets"
    env_file = secret_dir / "demo.env"
    assert env_file.is_file() and not env_file.is_symlink()
    assert stat.S_IMODE(os.stat(secret_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(env_file).st_mode) == 0o600
    keys = dict(line.split("=", 1) for line in env_file.read_text().splitlines() if "=" in line)
    assert len(keys["SESSION_SECRET"]) >= 32 and len(keys["HMAC_KEY"]) >= 32
    assert keys["LOGCARVE_ADMIN_PASSWORD"]
    assert "sha256" in result.stdout
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() in result.stdout


def test_init_is_idempotent_and_preserves_bytes(tmp_path):
    export = _stage_export(tmp_path)
    assert _run_init(export).returncode == 0
    env_file = export / "artifacts" / "local-demo-secrets" / "demo.env"
    before = env_file.read_bytes()
    second = _run_init(export)
    assert second.returncode == 0
    assert env_file.read_bytes() == before
    assert "existing bytes preserved" in second.stdout


def test_init_refuses_symlinked_parent(tmp_path):
    export = _stage_export(tmp_path)
    target = tmp_path / "link-target"
    target.mkdir()
    (export / "artifacts").symlink_to(target, target_is_directory=True)
    result = _run_init(export)
    assert result.returncode != 0
    assert "refusing symlinked path" in result.stderr
    assert list(target.iterdir()) == []


def test_init_refuses_symlinked_env_file(tmp_path):
    export = _stage_export(tmp_path)
    assert _run_init(export).returncode == 0
    env_file = export / "artifacts" / "local-demo-secrets" / "demo.env"
    before = env_file.read_bytes()
    elsewhere = tmp_path / "elsewhere.env"
    elsewhere.write_bytes(b"planted=1\n")
    env_file.unlink()
    env_file.symlink_to(elsewhere)
    result = _run_init(export)
    assert result.returncode != 0
    assert "refusing symlinked path" in result.stderr
    assert elsewhere.read_bytes() == b"planted=1\n"
    assert before != b"planted=1\n"
