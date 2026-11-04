"""Unit tests for the export spreadsheet-formula classifier (PAR-07).

No spreadsheet is launched and no formula is evaluated: every case
asserts the neutralizing prefix (or its absence) on the cell text.
All non-ASCII/control bytes use explicit escapes so the hazards stay
visible in review.
"""

from app.api.routes_export import _formula_triggered, csv_cell


def test_ascii_formula_leads_neutralized():
    assert csv_cell("=1+1") == "'=1+1"
    assert csv_cell("+evil-sum") == "'+evil-sum"
    assert csv_cell("-evil-diff") == "'-evil-diff"
    assert csv_cell("@macro-call") == "'@macro-call"
    assert csv_cell("  =padded-formula") == "'  =padded-formula"
    assert csv_cell("\t+tabbed") == "'\t+tabbed"


def test_nul_and_controls_before_lead_neutralized():
    # NUL, C0 controls and DEL (Cc) hide the lead from ASCII checks.
    assert csv_cell("\x00=1+1") == "'\x00=1+1"
    assert csv_cell("\x01\x02@macro") == "'\x01\x02@macro"
    assert csv_cell("\x7f-evil") == "'\x7f-evil"
    assert _formula_triggered("\x00=1+1") is True


def test_unicode_whitespace_before_lead_neutralized():
    # NBSP (Zs), OGHAM space (Zs), line separator (Zl).
    assert csv_cell("\u00a0=1+1") == "'\u00a0=1+1"
    assert csv_cell("\u1680@macro") == "'\u1680@macro"
    assert csv_cell("\u2028-evil") == "'\u2028-evil"
    assert _formula_triggered("\u00a0=1+1") is True


def test_format_bytes_before_lead_neutralized():
    # BOM and zero-width space (Cf) hide the lead from ASCII checks.
    assert csv_cell("\ufeff=1+1") == "'\ufeff=1+1"
    assert csv_cell("\u200b+evil") == "'\u200b+evil"
    assert _formula_triggered("\ufeff=1+1") is True


def test_original_text_preserved_behind_prefix():
    dangerous = "\u00a0\ufeff=1+1"
    protected = csv_cell(dangerous)
    assert protected == "'" + dangerous


def test_benign_text_untouched():
    assert csv_cell("Evil 'Quoted', Ünïcodé") == "Evil 'Quoted', Ünïcodé"
    assert csv_cell("/plain/path") == "/plain/path"
    assert csv_cell("a=b") == "a=b"
    assert csv_cell("") == ""
    assert csv_cell("   ") == "   "
    assert _formula_triggered("") is False
    assert _formula_triggered("   ") is False


def test_safe_null_and_numeric_semantics():
    assert csv_cell(None) == ""
    assert csv_cell(True) == "true"
    assert csv_cell(False) == "false"
    assert csv_cell(200) == 200
    assert csv_cell(0) == 0
    assert csv_cell(1.5) == 1.5
    assert csv_cell(float("nan")) == ""
    assert csv_cell(float("inf")) == ""
