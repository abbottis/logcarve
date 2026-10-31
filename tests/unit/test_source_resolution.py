"""T2 source-safety tests: administrative resolution, traversal/symlink
rejection and read-only access. All roots and files are synthetic and
live under pytest's tmp_path. The committed fixtures stay untouched.
"""

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ingestion.sources import SourceConfig, SourceError, identify_file, resolve_source_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _config(root: Path, relative: str, format_id: str = "nginx_combined") -> SourceConfig:
    return SourceConfig(
        source_id="example-combined", format_id=format_id, allowed_root=root, relative_path=relative
    )


def test_valid_source_resolves_inside_root(tmp_path):
    target = tmp_path / "access.txt"
    target.write_text("synthetic\n", encoding="utf-8")
    resolved = resolve_source_path(_config(tmp_path, "access.txt"))
    assert resolved == target.resolve()


def test_nested_relative_path_resolves(tmp_path):
    nested = tmp_path / "logs" / "2026"
    nested.mkdir(parents=True)
    target = nested / "access.txt"
    target.write_text("synthetic\n", encoding="utf-8")
    assert resolve_source_path(_config(tmp_path, "logs/2026/access.txt")) == target.resolve()


def test_absolute_path_rejected():
    with pytest.raises(ValidationError):
        _config(Path("/logs"), "/etc/passwd")


def test_parent_traversal_rejected():
    with pytest.raises(ValidationError):
        _config(Path("/logs"), "../outside.txt")
    with pytest.raises(ValidationError):
        _config(Path("/logs"), "sub/../../outside.txt")


def test_tilde_and_nul_rejected():
    with pytest.raises(ValidationError):
        _config(Path("/logs"), "~/access.txt")
    with pytest.raises(ValidationError):
        _config(Path("/logs"), "acc\x00ess.txt")


def test_unknown_format_rejected(tmp_path):
    with pytest.raises(ValidationError):
        _config(tmp_path, "access.txt", format_id="common")


def test_symlink_escape_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.txt").symlink_to(outside)
    with pytest.raises(SourceError, match="escapes its approved root"):
        resolve_source_path(_config(root, "link.txt"))


def test_symlink_inside_root_allowed(tmp_path):
    target = tmp_path / "access.txt"
    target.write_text("synthetic\n", encoding="utf-8")
    (tmp_path / "alias.txt").symlink_to(target)
    assert resolve_source_path(_config(tmp_path, "alias.txt")) == target.resolve()


def test_missing_file_rejected(tmp_path):
    with pytest.raises(SourceError, match="not a regular file"):
        resolve_source_path(_config(tmp_path, "absent.txt"))


def test_directory_rejected(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    with pytest.raises(SourceError, match="not a regular file"):
        resolve_source_path(_config(tmp_path, "sub"))


def test_missing_root_rejected(tmp_path):
    with pytest.raises(SourceError, match="not a directory"):
        resolve_source_path(_config(tmp_path / "nope", "access.txt"))


def test_file_identity_distinguishes_files(tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("a\n", encoding="utf-8")
    second.write_text("a\n", encoding="utf-8")
    assert identify_file(first) != identify_file(second)
    assert identify_file(first).size == 2


def test_read_only_access_leaves_source_untouched(tmp_path):
    from app.ingestion.stream import collect_records

    target = tmp_path / "access.txt"
    target.write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    records, report = collect_records(
        target, source_id="s", format_id="nginx_combined", hmac_key=b"synthetic-test-hmac-key"
    )
    assert report.accepted == len(records) == 10
    assert hashlib.sha256(target.read_bytes()).hexdigest() == before
