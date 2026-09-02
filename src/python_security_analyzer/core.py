"""Core Python security analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from python_security_analyzer.scanner import PyIssue, scan_python

TOOL_NAME = "python-security-analyzer"
TOOL_VERSION = "0.1.0"
_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    issues: list[PyIssue]


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_file(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"Python file not found: {resolved}")

    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    issues = scan_python(resolved)
    findings = _emit(issues, input_hash=input_hash, source=str(resolved), started=started)
    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=[InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size)],
            analysis_started_at=started,
            analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={"issue_count": len(issues)},
    )
    return AnalysisResult(report=report, issues=issues)


def _emit(issues: list[PyIssue], *, input_hash: str, source: str, started: Any) -> list[Finding]:
    findings: list[Finding] = [
        Finding(
            id=deterministic_finding_id("py-scan-observed", input_hash, {"n": len(issues)}),
            title=f"Python AST scan: {len(issues)} issue(s)",
            classification=Classification.OBSERVED,
            evidence=[Evidence(source=source, locator={"count": len(issues)}, retrieved_at=started)],
            method="Python AST pattern matching",
            why_it_matters="Static scan establishes code risk baseline.",
            plain_language=f"Found {len(issues)} potential security issues.",
            severity=Severity.INFO,
            tags=["python", "ast"],
            timestamp=started,
        )
    ]
    for issue in issues:
        findings.append(
            Finding(
                id=deterministic_finding_id("py-issue", input_hash, {"line": issue.line, "issue": issue.issue}),
                title=f"Python issue: {issue.issue} (line {issue.line})",
                classification=Classification.INFERRED,
                confidence=Confidence(
                    score=issue.confidence_score,
                    rationale=issue.detail,
                    supporting_indicators=[issue.excerpt],
                ),
                evidence=[
                    Evidence(
                        source=source,
                        locator={"line": issue.line, "issue": issue.issue},
                        excerpt=issue.excerpt,
                        retrieved_at=started,
                    )
                ],
                method="AST dangerous-call / secret / SQL heuristic",
                why_it_matters="Dangerous APIs and secrets in source enable compromise.",
                plain_language=f"{issue.detail} at line {issue.line}.",
                severity=_SEV.get(issue.severity, Severity.MEDIUM),
                tags=["python", issue.issue],
                timestamp=started,
            )
        )
    return findings
