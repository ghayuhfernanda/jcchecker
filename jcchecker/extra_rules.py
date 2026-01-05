from typing import List
import javalang
from javalang import tree as jtree

from .engine import Rule, Issue
from .emv_rules import WarnMissingEMVCommandsRule, PreferISO7816ConstantsRule


class EnforceAPDUReceiveBeforeGetBufferRule(Rule):
    def __init__(self):
        super().__init__("JC016", "Require apdu.setIncomingAndReceive() before using apdu.getBuffer() in process()", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "process":
                    continue
                has_get_buffer = False
                has_set_incoming = False
                for _, node in m.filter(jtree.MethodInvocation):
                    qualifier = node.qualifier or ""
                    member = node.member
                    if qualifier == "apdu" and member == "getBuffer":
                        has_get_buffer = True
                    if qualifier == "apdu" and member == "setIncomingAndReceive":
                        has_set_incoming = True
                if has_get_buffer and not has_set_incoming:
                    line = getattr(m, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "process(APDU) should call apdu.setIncomingAndReceive() before apdu.getBuffer()", file_path, line))
        return issues


class PreferTransientByteArrayRule(Rule):
    def __init__(self):
        super().__init__("JC017", "Prefer JCSystem.makeTransientByteArray for temporary arrays inside process()", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "process":
                    continue
                for _, node in m.filter(jtree.ArrayCreator):
                    # Detect new byte[] allocations inside process
                    try:
                        tname = getattr(node.type, "name", None)
                        if tname == "byte":
                            line = getattr(node, "position", None)
                            line = line[0] if line else None
                            issues.append(Issue(self.rule_id, self.severity, "Consider JCSystem.makeTransientByteArray for temporary buffers inside process()", file_path, line))
                    except Exception:
                        pass
        return issues


class RequireAppletRegisterRule(Rule):
    def __init__(self):
        super().__init__("JC018", "Require Applet.register() to be called in install()", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            is_applet = name.endswith("Applet") or (extends and extends.endswith("Applet"))
            if not is_applet:
                continue
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "install":
                    continue
                called_register = False
                for _, inv in m.filter(jtree.MethodInvocation):
                    member = inv.member
                    qualifier = inv.qualifier or ""
                    if member == "register":
                        # Accept this.register() or Applet.register(...)
                        called_register = True
                        break
                if not called_register:
                    line = getattr(m, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "install() should call Applet.register()", file_path, line))
        return issues


class NoForbiddenImportsRule(Rule):
    def __init__(self):
        super().__init__("JC019", "Disallow non-JavaCard packages (javax.crypto, java.security, java.net, java.nio)", "error")
        self.forbidden_prefixes = (
            "javax.crypto",
            "java.security",
            "java.net",
            "java.nio",
        )

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.Import):
            path = node.path or ""
            for pref in self.forbidden_prefixes:
                if path.startswith(pref):
                    line = getattr(node, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, f"Importing non-JavaCard package '{path}'", file_path, line))
                    break
        return issues


class NoSystemTimeRule(Rule):
    def __init__(self):
        super().__init__("JC020", "Disallow System.currentTimeMillis/nanoTime on JavaCard", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            member = node.member
            if qualifier == "System" and member in ("currentTimeMillis", "nanoTime"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Usage of System.{member}()", file_path, line))
        return issues


class EnforceIncomingBeforeReceiveBytesRule(Rule):
    def __init__(self):
        super().__init__("JC021", "Require apdu.setIncomingAndReceive() before apdu.receiveBytes()/getIncomingLength in process()", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "process":
                    continue
                used_receive_or_len = False
                has_set_incoming = False
                for _, node in m.filter(jtree.MethodInvocation):
                    qualifier = node.qualifier or ""
                    member = node.member
                    if qualifier == "apdu" and member in ("receiveBytes", "getIncomingLength"):
                        used_receive_or_len = True
                    if qualifier == "apdu" and member == "setIncomingAndReceive":
                        has_set_incoming = True
                if used_receive_or_len and not has_set_incoming:
                    line = getattr(m, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "process(APDU) should call apdu.setIncomingAndReceive() before apdu.receiveBytes()/getIncomingLength", file_path, line))
        return issues


class RequireSwitchDefaultInProcessRule(Rule):
    def __init__(self):
        super().__init__("JC022", "Require default branch in switch statements inside process(APDU)", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name != "process":
                    continue
                for _, sw in m.filter(jtree.SwitchStatement):
                    has_default = False
                    try:
                        for case in sw.cases or []:
                            labels = getattr(case, "labels", None)
                            if not labels:  # default case usually has no labels
                                has_default = True
                                break
                    except Exception:
                        pass
                    if not has_default:
                        line = getattr(sw, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, "Switch in process(APDU) should include a default that handles unsupported INS/CLA (e.g., ISOException.throwIt)", file_path, line))
        return issues


class WarnPersistentByteArrayFieldRule(Rule):
    def __init__(self):
        super().__init__("JC023", "Warn on class-level persistent byte[] fields; consider transient buffers for session data", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            for _, field in cls.filter(jtree.FieldDeclaration):
                # FieldDeclaration.type may be BasicType("byte") with dimensions
                t = getattr(field, "type", None)
                try:
                    if isinstance(t, jtree.BasicType) and t.name == "byte" and (t.dimensions and len(t.dimensions) >= 1):
                        mods = set(field.modifiers or [])
                        if "static" in mods:
                            continue  # JC012 covers static secrets separately
                        line = getattr(field, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, "Persistent class-level byte[] may consume EEPROM; consider JCSystem.makeTransientByteArray for session buffers", file_path, line))
                except Exception:
                    pass
        return issues


class EncourageOwnerPINRule(Rule):
    def __init__(self):
        super().__init__("JC024", "Encourage javacard.framework.OwnerPIN for PIN management when PINs are referenced", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        references_pin = False
        has_owner_pin = False
        for _, node in ast.filter(jtree.ReferenceType):
            name = node.name if isinstance(node.name, str) else ""
            base = name.split(".")[-1] if name else ""
            if base == "OwnerPIN":
                has_owner_pin = True
        # Look for identifiers that suggest PIN usage
        for _, node in ast.filter(jtree.VariableDeclarator):
            try:
                if node.name and ("pin" in node.name.lower()):
                    references_pin = True
            except Exception:
                pass
        for _, node in ast.filter(jtree.MemberReference):
            try:
                if node.member and ("pin" in node.member.lower()):
                    references_pin = True
            except Exception:
                pass
        if references_pin and not has_owner_pin:
            issues.append(Issue(self.rule_id, self.severity, "Code references PIN but does not use OwnerPIN; consider javacard.framework.OwnerPIN for retries and validation", file_path, None))
        return issues


class NoJavaUtilRandomRule(Rule):
    def __init__(self):
        super().__init__("JC025", "Disallow java.util.Random; use JavaCard random/PRNG facilities", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.Import):
            path = node.path or ""
            if path.startswith("java.util.Random"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing '{path}'", file_path, line))
        for _, node in ast.filter(jtree.ClassCreator):
            try:
                tname = getattr(node.type, "name", None)
                base = tname.split(".")[-1] if isinstance(tname, str) else ""
                if base == "Random":
                    line = getattr(node, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "Instantiation of java.util.Random", file_path, line))
            except Exception:
                pass
        return issues


class NoBigIntegerRule(Rule):
    def __init__(self):
        super().__init__("JC026", "Disallow java.math.BigInteger (unsupported on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.Import):
            path = node.path or ""
            if path.startswith("java.math.BigInteger"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing '{path}'", file_path, line))
        for _, node in ast.filter(jtree.ReferenceType):
            name = node.name if isinstance(node.name, str) else ""
            base = name.split(".")[-1] if name else ""
            if base == "BigInteger":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Reference to java.math.BigInteger", file_path, line))
        for _, node in ast.filter(jtree.ClassCreator):
            try:
                tname = getattr(node.type, "name", None)
                base = tname.split(".")[-1] if isinstance(tname, str) else ""
                if base == "BigInteger":
                    line = getattr(node, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, "Instantiation of java.math.BigInteger", file_path, line))
            except Exception:
                pass
        return issues


def get_additional_rules() -> List[Rule]:
    return [
        EnforceAPDUReceiveBeforeGetBufferRule(),
        PreferTransientByteArrayRule(),
        RequireAppletRegisterRule(),
        NoForbiddenImportsRule(),
        NoSystemTimeRule(),
        EnforceIncomingBeforeReceiveBytesRule(),
        RequireSwitchDefaultInProcessRule(),
        WarnPersistentByteArrayFieldRule(),
        EncourageOwnerPINRule(),
        NoJavaUtilRandomRule(),
        NoBigIntegerRule(),
        WarnMissingEMVCommandsRule(),
        PreferISO7816ConstantsRule(),
    ]