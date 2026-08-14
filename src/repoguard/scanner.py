"""Core scanning rules for RepoGuard."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    path_hint: str | None = None


RULES: tuple[Rule, ...] = (
    Rule("RG001", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key material detected"),
    Rule("RG002", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access-key identifier detected"),
    Rule("RG003", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "GitHub token-like value detected"),
    Rule("RG004", "medium", re.compile(r"(?i)\b(password|passwd|pwd)\s*=\s*['\"][^'\"\n]{8,}['\"]"), "Hard-coded password-like assignment detected"),
    Rule("RG101", "medium", re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.MULTILINE), "Workflow grants write-all permissions", ".github/workflows/"),
    Rule("RG102", "medium", re.compile(r"^\s*pull_request_target\s*:", re.MULTILINE), "pull_request_target workflow requires careful trust-boundary review", ".github/workflows/"),
    Rule("RG201", "medium", re.compile(r"subprocess\.(?:run|Popen|call|check_call|check_output)\([^\n]*shell\s*=\s*True"), "Python subprocess executes through a shell", ".py"),
)

SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
MAX_FILE_SIZE = 2 * 1024 * 1024


def _is_candidate(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return True


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _rule_applies(rule: Rule, relative: str) -> bool:
    if not rule.path_hint:
        return True
    if rule.path_hint.startswith(".") and "/" not in rule.path_hint:
        return relative.endswith(rule.path_hint)
    return rule.path_hint in relative


def scan_text(text: str, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        if not _rule_applies(rule, relative_path):
            continue
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    path=relative_path,
                    line=_line_number(text, match.start()),
                    message=rule.message,
                )
            )
    return findings


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if _is_candidate(path):
            yield path


def scan_path(root: str | Path) -> list[Finding]:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise FileNotFoundError(base)

    findings: list[Finding] = []
    for path in iter_files(base):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="ignore")
        relative = path.name if base.is_file() else path.relative_to(base).as_posix()
        findings.extend(scan_text(text, relative))

    return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))
