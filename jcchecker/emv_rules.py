from typing import List
import javalang
from javalang import tree as jtree

from .engine import Rule, Issue
from .recommendations import RULE_FIX_RECOMMENDATIONS


class WarnMissingEMVCommandsRule(Rule):
    def __init__(self):
        super().__init__("JC027", "Warn if EMV applet does not handle GPO (0xA8) or READ RECORD (0xB2)", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            # Only check if it looks like an Applet
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            is_applet = name.endswith("Applet") or (extends and extends.endswith("Applet"))
            if not is_applet:
                continue

            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "process":
                    continue
                
                # Check for 0xA8 (168) and 0xB2 (178) usage in process
                # This is a heuristic: we look for these literals in switch cases or if conditions
                has_gpo = False
                has_read_rec = False
                
                # Scan all literals in the method
                for _, literal in m.filter(jtree.Literal):
                    val = literal.value
                    try:
                        # literal.value is a string, e.g. "0xA8" or "168"
                        # Parse it
                        v_int = -1
                        if isinstance(val, str):
                            if val.lower().startswith("0x"):
                                v_int = int(val, 16)
                            elif val.isdigit():
                                v_int = int(val)
                        
                        if v_int == 0xA8: # 168
                            has_gpo = True
                        if v_int == 0xB2: # 178
                            has_read_rec = True
                    except Exception:
                        pass
                
                if not has_gpo:
                    line = getattr(m, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "Applet process() missing handler for GPO (0xA8)? (Required for EMV)", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
                if not has_read_rec:
                    line = getattr(m, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "Applet process() missing handler for READ RECORD (0xB2)? (Required for EMV)", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))

        return issues


class PreferISO7816ConstantsRule(Rule):
    def __init__(self):
        super().__init__("JC028", "Prefer ISO7816 constants over hardcoded status words", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            member = node.member
            if (qualifier == "ISOException" and member == "throwIt") or (member == "throwing"):
                if node.arguments:
                    arg = node.arguments[0]
                    # Unwrap cast: (short) 0x6A81 -> Cast(type=..., expression=Literal(value='0x6A81'))
                    if isinstance(arg, jtree.Cast):
                        arg = arg.expression

                    if isinstance(arg, jtree.Literal):
                        # If the argument is a literal number, warn
                        try:
                            val = arg.value
                            is_num = False
                            if isinstance(val, str):
                                if val.lower().startswith("0x") or val.isdigit():
                                    is_num = True
                            if is_num:
                                line = getattr(node, "position", None)
                                line = line[0] if line else None
                                issues.append(Issue(self.rule_id, self.severity, f"Hardcoded SW '{val}' used in exception; prefer ISO7816.* constants", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
                        except Exception:
                            pass
        return issues
