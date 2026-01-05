import os
from typing import List
import javalang

from .engine import Issue, apply_rules
from .rules import get_default_rules


def analyze_file(file_path: str) -> List[Issue]:
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        tree = javalang.parse.parse(source)
    except Exception as e:
        # Syntax or parse error – report as warning
        return [Issue(
            rule_id="JC000",
            severity="warning",
            message=f"Parse error: {e}",
            file=file_path,
            line=None,
        )]
    rules = get_default_rules()
    return apply_rules(tree, file_path, source, rules)


def analyze_path(target_path: str) -> List[Issue]:
    files: List[str] = []
    if os.path.isdir(target_path):
        for root, _, filenames in os.walk(target_path):
            for name in filenames:
                if name.lower().endswith(".java"):
                    files.append(os.path.join(root, name))
    elif os.path.isfile(target_path) and target_path.lower().endswith(".java"):
        files.append(target_path)
    else:
        return [Issue(
            rule_id="JC000",
            severity="warning",
            message="No Java files found or path is invalid",
            file=target_path,
            line=None,
        )]

    issues: List[Issue] = []
    for fp in files:
        issues.extend(analyze_file(fp))
    return issues