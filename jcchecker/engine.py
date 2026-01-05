import os
import json
from typing import List, Optional


class Issue:
    def __init__(self, rule_id: str, severity: str, message: str, file: str, line: Optional[int] = None, recommendation: Optional[str] = None):
        self.rule_id = rule_id
        self.severity = severity  # 'error' or 'warning'
        self.message = message
        self.file = file
        self.line = line
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "recommendation": self.recommendation,
        }

    def format_text(self):
        loc = f":{self.line}" if self.line else ""
        rec = f"\n  fix: {self.recommendation}" if self.recommendation else ""
        return f"{self.file}{loc}: {self.severity} {self.rule_id}: {self.message}{rec}"


class Rule:
    def __init__(self, rule_id: str, description: str, severity: str = "error"):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity

    def apply(self, tree, file_path: str, source: str) -> List[Issue]:  # pragma: no cover (interface)
        return []


def apply_rules(tree, file_path: str, source: str, rules: List[Rule]) -> List[Issue]:
    issues: List[Issue] = []
    for rule in rules:
        try:
            found = rule.apply(tree, file_path, source) or []
            issues.extend(found)
        except Exception as e:
            # Fail-safe: do not crash on one rule
            issues.append(Issue(
                rule_id=f"{rule.rule_id}-internal",
                severity="warning",
                message=f"Rule '{rule.rule_id}' failed: {e}",
                file=file_path,
                line=None,
            ))
    return issues