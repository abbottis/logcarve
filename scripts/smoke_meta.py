"""Finite T8 smoke runner: dry-run by default, explicit --real-run only.

Dry-run (default): seeds the synthetic T8 fixture into a scratch DB,
runs the three hand-derived investigations against a MOCK transport
through the real dispatch path (build, decoded validation, exact
bytes, verified pricing, lifetime smoke allowance), and asserts the
expected analytics. Dry-run never opens the product key file and
never touches the network: the mock transport raises if it is not
the injected mock.

Real-run: requires BOTH --real-run and --key-file, consumes the
persistent lifetime allowance (<=3 investigations, <=12 requests
incl. failures, <=USD1; tighter existing limits bind), and stops
before any cap. Writes a safe-metadata JSONL ledger only (model,
counts, cost, status -- never prompts, responses or evidence).

This approval never authorizes real execution: a real run needs a
separate explicit owner approval after independent review.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.ai import budget
from app.ai.providers.meta_responses import MetaResponsesAdapter
from app.ai.service import Actor, run_investigation
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.config import Settings
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ENDPOINT = "https://api.meta.ai/v1/responses"
MODEL = "muse-spark-1.3"

WINDOWS = {
    "A": (datetime(2026, 10, 26, 10, 0, tzinfo=UTC), datetime(2026, 10, 26, 11, 0, tzinfo=UTC)),
    "B": (datetime(2026, 10, 27, 14, 0, tzinfo=UTC), datetime(2026, 10, 27, 15, 0, tzinfo=UTC)),
    "C": (datetime(2026, 10, 28, 9, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC)),
}
QUESTIONS = {
    "A": "What claimed AI crawler activity is visible?",
    "B": "Which missing pages were requested and who referred them?",
    "C": "Which suspicious request patterns are visible?",
}


class MockTransport:
    """In-process Responses stand-in; any other transport is a failure."""

    def __init__(self, script: list[dict]) -> None:
        self.script = list(script)
        self.calls: list[dict] = []

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses", url
        assert headers.get("Content-Type") == "application/json"
        assert str(headers.get("Authorization", "")).startswith("Bearer ")
        assert isinstance(body, bytes) and body
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == MODEL
        assert payload["store"] is False
        assert "previous_response_id" not in payload
        self.calls.append({"bytes": len(body), "items": len(payload["input"])})
        # Simulated server accounting stays within the dispatched bounds
        # and mirrors the documented response shape (status/model/total).
        usage = {
            "input_tokens": min(len(body), 60000),
            "output_tokens": 25,
            "total_tokens": min(len(body), 60000) + 25,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 5},
        }
        step = self.script.pop(0) if self.script else {"text": "done"}
        output: list[dict] = []
        for index, call in enumerate(step.get("calls", [])):
            output.append(
                {
                    "type": "function_call",
                    "name": call["name"],
                    "arguments": json.dumps(call.get("arguments", {"limit": 5})),
                    "call_id": f"call_{len(self.calls)}_{index}",
                    "status": "completed",
                }
            )
        if step.get("text") is not None:
            output.append(
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": step["text"]}],
                }
            )
        return {
            "id": f"resp_mock_{len(self.calls)}",
            "model": MODEL,
            "status": "completed",
            "output": output,
            "usage": usage,
        }


def seed_db(db: Path, logs_root: Path) -> None:
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=logs_root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=b"synthetic-smoke-hmac-key",
    )


def dry_run(root: Path) -> int:
    """Full pipeline with mock transport; proves zero key access/network."""
    import os
    import tempfile

    from app.ai import smoke as smoke_mod

    # Dry-run-only synthetic secrets so the script runs standalone
    # without an operator .env. Real runs use operator configuration.
    os.environ.setdefault("SESSION_SECRET", "dry-run-synthetic-secret")
    os.environ.setdefault("HMAC_KEY", "dry-run-synthetic-key")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        logs_root = tmp_path / "logs"
        logs_root.mkdir()
        (logs_root / "access.log").write_bytes(
            (root / "tests" / "fixtures" / "combined" / "t8_smoke.txt").read_bytes()
        )
        db = tmp_path / "smoke.sqlite3"
        seed_db(db, logs_root)
        rules = (
            load_rules(root / "config" / "bot_rules.yaml").rules
            + load_rules(root / "config" / "security_rules.yaml").rules
        )
        settings = Settings(
            ai_enabled=True,
            model_data_policy_verified=True,
            model_allow_real_data=True,
            model_endpoint=ENDPOINT,
            llm_daily_limit_usd=50.0,
            llm_budget_usd=150.0,
            llm_warn_at_usd=120.0,
            llm_stop_at_usd=140.0,
        )
        actor = Actor(kind="admin", username="admin", session_id="dry-run")
        scripts = {
            "A": [
                {"calls": [{"name": "get_crawler_claims", "arguments": {"limit": 10}}]},
                {"text": "Claimed GPTBot and ClaudeBot activity is visible with limits."},
            ],
            "B": [
                {"calls": [{"name": "get_error_groups", "arguments": {"limit": 10}}]},
                {"text": "Five missing-page requests arrived from two referrers."},
            ],
            "C": [
                {"calls": [{"name": "get_security_findings", "arguments": {"limit": 10}}]},
                {"text": "Two candidate findings are visible with rule references."},
            ],
        }
        ledger: list[dict] = []
        for case in ("A", "B", "C"):
            time_from, time_to = WINDOWS[case]
            transport = MockTransport(scripts[case])
            provider = MetaResponsesAdapter(
                endpoint=ENDPOINT,
                model=MODEL,
                api_key="dry-run-placeholder-never-sent",
                transport=transport,
            )
            result = run_investigation(
                db_path=db,
                rules=rules,
                settings=settings,
                provider=provider,
                actor=actor,
                question=QUESTIONS[case],
                site_id="default",
                source_id=None,
                time_from=time_from,
                time_to=time_to,
                smoke_enforced=True,
            )
            assert result.tool_calls >= 1, case
            assert result.usage.get("pricing_version") == "2026-10-31-dev.meta.ai", case
            ledger.append(
                {
                    "case": case,
                    "status": "completed",
                    "model": result.model,
                    "input_tokens": result.usage["input_tokens"],
                    "output_tokens": result.usage["output_tokens"],
                    "cached_tokens": result.usage.get("cached_tokens", 0),
                    "reasoning_tokens": result.usage.get("reasoning_tokens", 0),
                    "tool_calls": result.tool_calls,
                    "estimated_cost_usd": result.usage["estimated_cost_usd"],
                    "duration_s": result.usage["duration_s"],
                    "provider_requests": len(transport.calls),
                }
            )
        state = smoke_mod.init_or_check(
            db,
            max_investigations=3,
            max_requests=12,
            max_micro_usd=budget.usd_to_micro(1.0),
        )
        assert state["used_investigations"] == 3, state
        assert 3 <= state["used_requests"] <= 12, state
        assert state["used_micro_usd"] > 0, state
        total_cost = sum(entry["estimated_cost_usd"] for entry in ledger)
        assert total_cost <= 1.0, total_cost
        print(f"dry-run OK: 3 investigations, {state['used_requests']} requests, ${total_cost:.6f}")
        print("key file untouched (never opened); network untouched (mock transport only).")
    return 0


class PreflightError(RuntimeError):
    """The local dataset is not the verified synthetic smoke fixture."""


class OutputRefused(RuntimeError):
    """A result/ledger output path is unsafe or collides."""


FIXTURE_PATH = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
STAGING_LOG_NAME = "access.log"


def _fixture_bytes() -> tuple[bytes, str]:
    """Read the committed fixture read-only with its SHA256 provenance."""
    import hashlib

    raw = FIXTURE_PATH.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest()


def _ensure_staging_log(staging_root: Path, fixture_raw: bytes) -> Path:
    """Provide the seed source without ever harming an existing file.

    Missing file: exclusive no-follow creation (0600) owned by this run.
    Existing file: symlink (or non-regular) refused; byte-exact fixture
    reused read-only; anything else refused. Never truncates, moves,
    deletes, chmods, or follows symlinks.
    """
    import os
    import stat as stat_mod

    root = Path(staging_root)
    if os.path.lexists(root):
        if not root.is_dir() or root.is_symlink():
            raise PreflightError(f"refusing unsafe staging root: {root}")
    else:
        root.mkdir(parents=True, exist_ok=True)
    target = root / STAGING_LOG_NAME
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        try:
            os.write(fd, fixture_raw)
        finally:
            os.close(fd)
        return target
    st = os.lstat(target)
    if stat_mod.S_ISLNK(st.st_mode):
        raise PreflightError(f"refusing symlinked source: {target}")
    if not stat_mod.S_ISREG(st.st_mode):
        raise PreflightError(f"refusing non-regular source: {target}")
    with open(target, "rb") as handle:
        existing = handle.read()
    if existing != fixture_raw:
        raise PreflightError(f"refusing foreign existing source: {target}")
    return target


def _verify_provenance(conn, fixture_sha: str) -> tuple[int, list[int]]:
    """Verify exact synthetic provenance read-only (never counts alone).

    Every imports row for the single source must be completed,
    unflagged, and fingerprinted with the exact committed fixture
    SHA256; no other sites, sources, or rows may exist.
    """
    sites = [row[0] for row in conn.execute("SELECT id FROM sites ORDER BY id")]
    sources = [
        row[0]
        for row in conn.execute("SELECT id FROM log_sources WHERE site_id = 'default' ORDER BY id")
    ]
    total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    if sites != ["default"] or sources != ["example-combined"] or total != 30:
        raise PreflightError(f"unexpected dataset: sites={sites} sources={sources} rows={total}")
    extra_sites = conn.execute("SELECT DISTINCT site_id FROM requests").fetchall()
    extra_sources = conn.execute("SELECT DISTINCT source_id FROM requests").fetchall()
    if [row[0] for row in extra_sites] != ["default"] or [row[0] for row in extra_sources] != [
        "example-combined"
    ]:
        raise PreflightError("unexpected request ownership in store")
    foreign_imports = conn.execute(
        "SELECT COUNT(*) FROM imports WHERE source_id != 'example-combined'"
    ).fetchone()[0]
    if foreign_imports:
        raise PreflightError("unexpected foreign imports in store")
    for import_id, status, summary, fingerprint in conn.execute(
        "SELECT id, status, error_summary, file_fingerprint FROM imports"
        " WHERE source_id = 'example-combined' ORDER BY id"
    ).fetchall():
        if status != "completed" or summary or fingerprint != fixture_sha:
            raise PreflightError(f"unverified import provenance: id={import_id}")
    counts = []
    for case in ("A", "B", "C"):
        time_from, time_to = WINDOWS[case]
        counts.append(
            conn.execute(
                "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND ts_utc < ?",
                (time_from.isoformat(), time_to.isoformat()),
            ).fetchone()[0]
        )
    if counts != [12, 10, 8]:
        raise PreflightError(f"unexpected case windows: {counts}")
    return total, counts


def preflight(db: Path, staging_root: Path, rules, hmac_key: bytes) -> dict:
    """Seed (when empty) and verify the known 30-row single-source fixture.

    Existing non-empty stores are recognized read-only BEFORE any
    migration, seed, or key load; foreign or unrecognized stores are
    refused untouched. Fresh owned databases migrate, seed from an
    exclusively created (or byte-exact reused) fixture copy, and then
    verify identically. No source logs are edited, moved or deleted.
    """
    from app.analytics.contracts import AnalyticsFilter, TimeWindow
    from app.analytics.service import crawler_claims, security_findings
    from app.db.database import connect

    fixture_raw, fixture_sha = _fixture_bytes()
    db_path = Path(db)
    fresh = not (db_path.exists() and db_path.stat().st_size > 0)
    if fresh:
        staging_log = _ensure_staging_log(Path(staging_root), fixture_raw)
        migrate(db_path)
        run_import(
            db_path,
            source=SourceConfig(
                source_id="example-combined",
                format_id="nginx_combined",
                allowed_root=staging_log.parent,
                relative_path=staging_log.name,
            ),
            site_id="default",
            site_name="s",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="access.log",
            hmac_key=hmac_key,
        )
    else:
        conn = connect(db_path, read_only=True)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not {"sites", "log_sources", "imports", "requests"} <= tables:
                raise PreflightError("unrecognized existing store")
            _verify_provenance(conn, fixture_sha)
        finally:
            conn.close()
        migrate(db_path)
    conn = connect(db_path, read_only=True)
    try:
        total, counts = _verify_provenance(conn, fixture_sha)
        from app.analytics import queries

        bot_rules = [rule for rule in rules if rule.ua_contains]
        sec_rules = [rule for rule in rules if rule.path_contains or rule.min_client_errors]

        def window_filt(case):
            start, end = WINDOWS[case]
            return AnalyticsFilter(
                site_id="default", window=TimeWindow(time_from=start, time_to=end)
            )

        claims = crawler_claims(conn, window_filt("A"), bot_rules)
        got = sorted((finding.rule_id, finding.counts["requests"]) for finding in claims)
        if got != [("bot-ai-claude", 2), ("bot-ai-gpt", 7)]:
            raise PreflightError(f"unexpected crawler aggregates: {got}")
        groups, groups_total = queries.error_groups(conn, window_filt("B"))
        if groups_total != 1 or groups[0]["requests"] != 5:
            raise PreflightError(f"unexpected 404 aggregates: {groups_total}")
        findings = security_findings(conn, window_filt("C"), sec_rules)
        if len(findings) != 2:
            raise PreflightError(f"unexpected security findings: {len(findings)}")
    finally:
        conn.close()
    return {"rows": total, "windows": counts}


def _append_owned(path: Path, obj: dict, *, owned: set, protected: set) -> None:
    """Append one JSONL record to an owned output file (0600 from creation).

    Fresh files are exclusively created 0600 and registered as owned;
    files this run created may append. Symlinks, non-regular files,
    collisions with the key/source/DB paths, and any pre-existing file
    this run did not create are refused — actual ledgers are never
    merged into, overwritten, or reset. No chmod is ever applied.
    """
    import os
    import stat as stat_mod

    target = os.path.abspath(path)
    if target in protected:
        raise OutputRefused(f"refusing output colliding with protected path: {path}")
    line = (json.dumps(obj, sort_keys=True) + "\n").encode("utf-8")
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
        owned.add(target)
        return
    if stat_mod.S_ISLNK(st.st_mode):
        raise OutputRefused(f"refusing symlinked output: {path}")
    if not stat_mod.S_ISREG(st.st_mode):
        raise OutputRefused(f"refusing non-regular output: {path}")
    if target not in owned:
        raise OutputRefused(f"refusing pre-existing output (choose a fresh path): {path}")
    with open(target, "ab") as handle:
        handle.write(line)


def _claim_output(path: Path, *, owned: set, protected: set) -> None:
    """Exclusively claim a fresh 0600 output before any dispatch.

    Any pre-existing path — regular, symlink, or otherwise — is refused
    so actual ledgers are never merged into or reset and no unrelated
    file is altered. No chmod is ever applied.
    """
    import os

    target = os.path.abspath(path)
    if target in protected:
        raise OutputRefused(f"refusing output colliding with protected path: {path}")
    if os.path.lexists(target):
        raise OutputRefused(f"refusing pre-existing output (choose a fresh path): {path}")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    owned.add(target)


def _safe_ledger_entry(case: str, result) -> dict:
    """Safe durable usage/status metadata only: no prompts or content."""
    return {
        "case": case,
        "status": "completed",
        "model": result.model,
        "input_tokens": result.usage["input_tokens"],
        "output_tokens": result.usage["output_tokens"],
        "cached_tokens": result.usage.get("cached_tokens", 0),
        "reasoning_tokens": result.usage.get("reasoning_tokens", 0),
        "tool_calls": result.tool_calls,
        "response_ids": result.response_ids,
        "estimated_cost_usd": result.usage["estimated_cost_usd"],
        "duration_s": result.usage["duration_s"],
        "observation_time": result.observation_time,
    }


def real_run(args, *, transport=None) -> int:
    """Capped real execution. Requires separate owner approval (NOT granted).

    Honors the operator's verified configuration: --real-run alone
    never enables data handling. `transport` is a test-only injection
    for the offline entry test; production always uses native HTTPS.
    """
    from app.ai import smoke as smoke_mod

    settings = Settings()
    if not settings.ai_enabled:
        print("refusing real run: AI is not enabled in operator config", file=sys.stderr)
        return 2
    if not (settings.model_data_policy_verified and settings.model_allow_real_data):
        print(
            "refusing real run: verified data policy and explicit real-data"
            " approval are required in operator config",
            file=sys.stderr,
        )
        return 2
    endpoint = settings.model_endpoint or args.endpoint
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    db = Path(args.db)
    try:
        info = preflight(
            db,
            Path(args.staging),
            rules,
            settings.hmac_key.get_secret_value().encode("utf-8"),
        )
    except PreflightError as exc:
        print(f"refusing real run: {exc}", file=sys.stderr)
        return 2
    print(f"preflight OK: {info}")
    try:
        state = smoke_mod.init_or_check(
            db,
            max_investigations=settings.smoke_max_investigations,
            max_requests=settings.smoke_max_requests,
            max_micro_usd=budget.usd_to_micro(settings.smoke_budget_usd),
        )
    except smoke_mod.SmokeRefused as exc:
        print(f"refusing real run: {exc}", file=sys.stderr)
        return 2
    print(f"allowance before run: {state}")
    key_path = Path(args.key_file)
    try:
        key_value = key_path.read_text(encoding="utf-8").splitlines()[0].strip()
    except OSError as exc:
        print(f"refusing real run: cannot read key file: {exc}", file=sys.stderr)
        return 2
    if not key_value:
        print("refusing real run: key file is empty", file=sys.stderr)
        return 2
    provider = MetaResponsesAdapter(
        endpoint=endpoint, model=MODEL, api_key=key_value, transport=transport
    )
    import os

    ledger_path = Path(args.ledger)
    results_path = Path(args.results)
    protected = {
        os.path.abspath(key_path),
        os.path.abspath(db),
        os.path.abspath(Path(args.staging) / STAGING_LOG_NAME),
    }
    owned: set = set()
    try:
        for output_path in (ledger_path, results_path):
            _claim_output(output_path, owned=owned, protected=protected)
    except OutputRefused as exc:
        print(f"refusing real run: {exc}", file=sys.stderr)
        return 2
    actor = Actor(kind="admin", username="admin", session_id="smoke-run")

    def record(entry: dict, application_result: dict | None = None) -> int:
        """Append ledger (+result) entries; 2 when the output is refused."""
        try:
            _append_owned(ledger_path, entry, owned=owned, protected=protected)
            _append_owned(
                results_path,
                application_result if application_result is not None else entry,
                owned=owned,
                protected=protected,
            )
        except OutputRefused as exc:
            print(f"refusing real run: {exc}", file=sys.stderr)
            return 2
        return 0

    failed = False
    for case in ("A", "B", "C"):
        time_from, time_to = WINDOWS[case]
        try:
            result = run_investigation(
                db_path=db,
                rules=rules,
                settings=settings,
                provider=provider,
                actor=actor,
                question=QUESTIONS[case],
                site_id="default",
                source_id=None,
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:  # noqa: BLE001 - runner records failures, never raises
            entry = {
                "case": case,
                "status": "failed",
                "model": MODEL,
                "code": getattr(exc, "code", type(exc).__name__),
                "message": str(exc),
            }
            refused = record(entry)
            if refused:
                return refused
            print(f"case {case}: FAILED ({entry['code']})", file=sys.stderr)
            failed = True
            continue
        # A case succeeds only with actual tools and evidence; never
        # consume extra investigations to manufacture a pass.
        if result.tool_calls < 1 or not result.evidence:
            entry = {
                "case": case,
                "status": "failed",
                "model": result.model,
                "code": "missing_evidence",
                "message": "The investigation produced no tool evidence.",
            }
            refused = record(entry)
            if refused:
                return refused
            print(f"case {case}: FAILED (missing_evidence)", file=sys.stderr)
            failed = True
            continue
        entry = _safe_ledger_entry(case, result)
        application_result = {
            "case": case,
            "status": "completed",
            "answer": result.answer_text,
            "model": result.model,
            "provider": result.provider,
            "investigation_id": result.investigation_id,
            "tool_calls": result.tool_calls,
            "response_ids": result.response_ids,
            "provider_calls": result.provider_calls,
            "evidence": result.evidence,
            "usage": {
                "input_tokens": result.usage["input_tokens"],
                "output_tokens": result.usage["output_tokens"],
                "cached_tokens": result.usage.get("cached_tokens", 0),
                "reasoning_tokens": result.usage.get("reasoning_tokens", 0),
                "estimated_cost_usd": result.usage["estimated_cost_usd"],
                "pricing_version": result.usage.get("pricing_version"),
            },
            "warnings": result.warnings,
            "observation_time": result.observation_time,
        }
        refused = record(entry, application_result)
        if refused:
            return refused
        print(f"case {case}: tools={result.tool_calls} cost=${entry['estimated_cost_usd']:.6f}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Finite T8 smoke runner (dry-run default).")
    parser.add_argument("--real-run", action="store_true", help="explicit real execution")
    parser.add_argument("--key-file", default="artifacts/local-demo-secrets/MODEL_API_KEY")
    parser.add_argument("--endpoint", default=ENDPOINT)
    parser.add_argument("--db", default="data/smoke.sqlite3")
    parser.add_argument("--ledger", default="data/smoke-ledger.jsonl")
    parser.add_argument("--results", default="data/smoke-results.jsonl")
    parser.add_argument("--staging", default="data/smoke-logs")
    args = parser.parse_args(argv)
    if not args.real_run:
        return dry_run(ROOT)
    return real_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
