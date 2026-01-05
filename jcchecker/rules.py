from typing import List
import javalang
from javalang import tree as jtree

from .engine import Rule, Issue
from .recommendations import RULE_FIX_RECOMMENDATIONS


class NoFloatDoubleRule(Rule):
    def __init__(self):
        super().__init__("JC001", "Disallow usage of float/double types (not supported on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        # Primitive float/double
        for _, node in ast.filter(jtree.BasicType):
            if node.name in ("float", "double"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Usage of primitive type '{node.name}'", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        # Wrapper types Float/Double
        for _, node in ast.filter(jtree.ReferenceType):
            # node.name can be like 'Float' or 'java.lang.Float'
            name = node.name if isinstance(node.name, str) else None
            if name:
                base = name.split(".")[-1]
                if base in ("Float", "Double"):
                    line = getattr(node, "position", None)
                    line = line[0] if line else None
                    issues.append(Issue(self.rule_id, self.severity, f"Usage of wrapper type '{base}'", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoJavaIoRule(Rule):
    def __init__(self):
        super().__init__("JC002", "Disallow java.io package (not supported on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.Import):
            path = node.path or ""
            if path.startswith("java.io"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing '{path}'", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoReflectionRule(Rule):
    def __init__(self):
        super().__init__("JC003", "Disallow reflection APIs (java.lang.reflect, Class.forName, newInstance)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        # Imports from java.lang.reflect
        for _, node in ast.filter(jtree.Import):
            path = node.path or ""
            if path.startswith("java.lang.reflect"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing reflection API '{path}'", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        # Class.forName / newInstance
        for _, node in ast.filter(jtree.MethodInvocation):
            name = node.member
            qualifier = node.qualifier or ""
            qlast = qualifier.split(".")[-1] if qualifier else ""
            if name == "forName" and qlast in ("Class", "java.lang.Class"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Dynamic class loading via Class.forName", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
            if name == "newInstance":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Dynamic instantiation via newInstance", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoSystemOutRule(Rule):
    def __init__(self):
        super().__init__("JC004", "Disallow System.out/System.err usage", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        # Direct references to System.out or System.err
        for _, node in ast.filter(jtree.MemberReference):
            member = node.member
            qualifier = node.qualifier or ""
            if qualifier == "System" and member in ("out", "err"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Usage of System.{member}", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        # Method invocations using System.out/err
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            if qualifier in ("System.out", "System.err"):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Method call via {qualifier}", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoFinalizeRule(Rule):
    def __init__(self):
        super().__init__("JC005", "Disallow finalize() method (not supported on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodDeclaration):
            if node.name == "finalize" and (not node.parameters):
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Definition of finalize() method", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoSynchronizedRule(Rule):
    def __init__(self):
        super().__init__("JC006", "Disallow synchronized keyword and blocks (no threads on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        # Synchronized blocks
        for _, node in ast.filter(jtree.SynchronizedStatement):
            line = getattr(node, "position", None)
            line = line[0] if line else None
            issues.append(Issue(self.rule_id, self.severity, "Synchronized block", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        # Synchronized method modifier
        for _, node in ast.filter(jtree.MethodDeclaration):
            mods = set(node.modifiers or [])
            if "synchronized" in mods:
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Synchronized method", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


def get_default_rules() -> List[Rule]:
    from .extra_rules import get_additional_rules
    return [
        NoFloatDoubleRule(),
        NoJavaIoRule(),
        NoReflectionRule(),
        NoSystemOutRule(),
        NoFinalizeRule(),
        NoSynchronizedRule(),
        RequireAppletSubclassRule(),
        RequireInstallSignatureRule(),
        RequireProcessSignatureRule(),
        PreferISOExceptionRule(),
        NoStringForSecretsRule(),
        NoStaticSecretByteArrayRule(),
        NoThreadUsageRule(),
        NoSystemGCRule(),
        AvoidArraysEqualsForSecretsRule(),
    ] + get_additional_rules()


class RequireAppletSubclassRule(Rule):
    def __init__(self):
        super().__init__("JC007", "Classes named *Applet or defining install/process should extend javacard.framework.Applet", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            defines_install_or_process = False
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name in ("install", "process"):
                    defines_install_or_process = True
                    break
            if (name.endswith("Applet") or defines_install_or_process) and not (extends and extends.endswith("Applet")):
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Class '{name}' should extend javacard.framework.Applet", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class RequireInstallSignatureRule(Rule):
    def __init__(self):
        super().__init__("JC008", "Require JavaCard install signature: public static void install(byte[] bArray, short bOffset, byte bLength)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            has_install = False
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name == "install":
                    has_install = True
                    mods = set(m.modifiers or [])
                    ok_mods = ("public" in mods and "static" in mods)
                    params = m.parameters or []
                    ok_params = False
                    if len(params) == 3:
                        p0, p1, p2 = params
                        try:
                            t0 = p0.type.name == "byte" and (p0.type.dimensions and len(p0.type.dimensions) >= 1)
                        except Exception:
                            t0 = False
                        t1 = getattr(p1.type, "name", None) == "short"
                        t2 = getattr(p2.type, "name", None) == "byte"
                        ok_params = t0 and t1 and t2
                    if not (ok_mods and ok_params):
                        line = getattr(m, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, "install method signature should be: public static void install(byte[] bArray, short bOffset, byte bLength)", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
            # If class is likely an applet, require install presence
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            if (name.endswith("Applet") or (extends and extends.endswith("Applet"))) and not has_install:
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Missing install(...) method in applet class", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class RequireProcessSignatureRule(Rule):
    def __init__(self):
        super().__init__("JC009", "Require JavaCard process signature: public void process(APDU apdu)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            is_applet = False
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            if name.endswith("Applet") or (extends and extends.endswith("Applet")):
                is_applet = True
            has_process = False
            bad_signature_line = None
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name == "process":
                    has_process = True
                    mods = set(m.modifiers or [])
                    ok_mods = ("public" in mods)
                    params = m.parameters or []
                    ok_params = False
                    if len(params) == 1:
                        p0 = params[0]
                        # Accept APDU or fully qualified javacard.framework.APDU
                        t0name = getattr(p0.type, "name", None)
                        if isinstance(t0name, str):
                            base = t0name.split(".")[-1]
                        else:
                            base = None
                        ok_params = (base == "APDU")
                    if not (ok_mods and ok_params):
                        pos = getattr(m, "position", None)
                        bad_signature_line = pos[0] if pos else None
                        issues.append(Issue(self.rule_id, self.severity, "process method signature should be: public void process(APDU apdu)", file_path, bad_signature_line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
            if is_applet and not has_process:
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Missing process(APDU) method in applet class", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class PreferISOExceptionRule(Rule):
    def __init__(self):
        super().__init__("JC010", "Prefer ISOException.throwIt; avoid throwing generic Exceptions on JavaCard", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        bad_exceptions = {"Exception", "RuntimeException", "IllegalArgumentException", "IllegalStateException"}
        for _, node in ast.filter(jtree.ThrowStatement):
            expr = node.expression
            bad = False
            typename = None
            if isinstance(expr, jtree.ClassCreator):
                tname = getattr(expr.type, "name", None)
                typename = tname.split(".")[-1] if isinstance(tname, str) else tname
                if typename in bad_exceptions:
                    bad = True
            if bad:
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Avoid throwing '{typename}'. Prefer ISOException.throwIt(...)", file_path, line))
        return issues


class NoStringForSecretsRule(Rule):
    def __init__(self):
        super().__init__("JC011", "Avoid using String to store secrets (PINs/keys). Use byte[] and secure handling.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, field in ast.filter(jtree.FieldDeclaration):
            tname = getattr(field.type, "name", None)
            if tname == "String":
                for declarator in field.declarators or []:
                    vname = getattr(declarator, "name", None)
                    if _is_sensitive_name(vname):
                        line = getattr(field, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, f"Field '{vname}' typed as String may expose secrets", file_path, line))
        return issues


class NoStaticSecretByteArrayRule(Rule):
    def __init__(self):
        super().__init__("JC012", "Avoid storing secrets in static byte[] fields; prefer transient arrays or key objects.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, field in ast.filter(jtree.FieldDeclaration):
            mods = set(field.modifiers or [])
            if "static" in mods:
                try:
                    is_byte_array = getattr(field.type, "name", None) == "byte" and (field.type.dimensions and len(field.type.dimensions) >= 1)
                except Exception:
                    is_byte_array = False
                if is_byte_array:
                    for declarator in field.declarators or []:
                        vname = getattr(declarator, "name", None)
                        if _is_sensitive_name(vname):
                            line = getattr(field, "position", None)
                            line = line[0] if line else None
                            issues.append(Issue(self.rule_id, self.severity, f"Static byte[] field '{vname}' may hold secrets persistently", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoThreadUsageRule(Rule):
    def __init__(self):
        super().__init__("JC013", "Disallow Thread usage (no multi-threading on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, imp in ast.filter(jtree.Import):
            path = imp.path or ""
            if path.startswith("java.lang.Thread"):
                line = getattr(imp, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing '{path}'", file_path, line))
        for _, ref in ast.filter(jtree.ReferenceType):
            name = ref.name if isinstance(ref.name, str) else None
            if name and name.split(".")[-1] == "Thread":
                line = getattr(ref, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Usage of Thread type", file_path, line))
        for _, cc in ast.filter(jtree.ClassCreator):
            tname = getattr(cc.type, "name", None)
            if isinstance(tname, str) and tname.split(".")[-1] == "Thread":
                line = getattr(cc, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Creation of Thread instance", file_path, line))
        return issues


class NoSystemGCRule(Rule):
    def __init__(self):
        super().__init__("JC014", "Disallow System.gc() on JavaCard", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            if qualifier == "System" and node.member == "gc":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Usage of System.gc()", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class AvoidArraysEqualsForSecretsRule(Rule):
    def __init__(self):
        super().__init__("JC015", "Avoid Arrays.equals for secret comparison; consider constant-time checks.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            if qualifier == "Arrays" and node.member == "equals":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Arrays.equals() may leak timing information for secret data", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


# --- JavaCard Applet and Security-focused rules ---

SENSITIVE_NAMES = ("pin", "key", "secret", "pwd", "password")

def _is_sensitive_name(name: str) -> bool:
    lname = (name or "").lower()
    return any(k in lname for k in SENSITIVE_NAMES)


class RequireAppletSubclassRule(Rule):
    def __init__(self):
        super().__init__("JC007", "Classes named *Applet or defining install/process should extend javacard.framework.Applet", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            defines_install_or_process = False
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name in ("install", "process"):
                    defines_install_or_process = True
                    break
            if (name.endswith("Applet") or defines_install_or_process) and not (extends and extends.endswith("Applet")):
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Class '{name}' should extend javacard.framework.Applet", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class RequireInstallSignatureRule(Rule):
    def __init__(self):
        super().__init__("JC008", "Require JavaCard install signature: public static void install(byte[] bArray, short bOffset, byte bLength)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            has_install = False
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name == "install":
                    has_install = True
                    mods = set(m.modifiers or [])
                    ok_mods = ("public" in mods and "static" in mods)
                    params = m.parameters or []
                    ok_params = False
                    if len(params) == 3:
                        p0, p1, p2 = params
                        try:
                            t0 = p0.type.name == "byte" and (p0.type.dimensions and len(p0.type.dimensions) >= 1)
                        except Exception:
                            t0 = False
                        t1 = getattr(p1.type, "name", None) == "short"
                        t2 = getattr(p2.type, "name", None) == "byte"
                        ok_params = t0 and t1 and t2
                    if not (ok_mods and ok_params):
                        line = getattr(m, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, "install method signature should be: public static void install(byte[] bArray, short bOffset, byte bLength)", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
            # If class is likely an applet, require install presence
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            if (name.endswith("Applet") or (extends and extends.endswith("Applet"))) and not has_install:
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Missing install(...) method in applet class", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class RequireProcessSignatureRule(Rule):
    def __init__(self):
        super().__init__("JC009", "Require JavaCard process signature: public void process(APDU apdu)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, cls in ast.filter(jtree.ClassDeclaration):
            is_applet = False
            name = cls.name or ""
            extends = cls.extends.name if getattr(cls, "extends", None) else None
            if name.endswith("Applet") or (extends and extends.endswith("Applet")):
                is_applet = True
            has_process = False
            bad_signature_line = None
            for _, m in cls.filter(jtree.MethodDeclaration):
                if m.name == "process":
                    has_process = True
                    mods = set(m.modifiers or [])
                    ok_mods = ("public" in mods)
                    params = m.parameters or []
                    ok_params = False
                    if len(params) == 1:
                        p0 = params[0]
                        # Accept APDU or fully qualified javacard.framework.APDU
                        t0name = getattr(p0.type, "name", None)
                        if isinstance(t0name, str):
                            base = t0name.split(".")[-1]
                        else:
                            base = None
                        ok_params = (base == "APDU")
                    if not (ok_mods and ok_params):
                        pos = getattr(m, "position", None)
                        bad_signature_line = pos[0] if pos else None
                        issues.append(Issue(self.rule_id, self.severity, "process method signature should be: public void process(APDU apdu)", file_path, bad_signature_line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
            if is_applet and not has_process:
                line = getattr(cls, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Missing process(APDU) method in applet class", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class PreferISOExceptionRule(Rule):
    def __init__(self):
        super().__init__("JC010", "Prefer ISOException.throwIt; avoid throwing generic Exceptions on JavaCard", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        bad_exceptions = {"Exception", "RuntimeException", "IllegalArgumentException", "IllegalStateException"}
        for _, node in ast.filter(jtree.ThrowStatement):
            expr = node.expression
            bad = False
            typename = None
            if isinstance(expr, jtree.ClassCreator):
                tname = getattr(expr.type, "name", None)
                typename = tname.split(".")[-1] if isinstance(tname, str) else tname
                if typename in bad_exceptions:
                    bad = True
            if bad:
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Avoid throwing '{typename}'. Prefer ISOException.throwIt(...)", file_path, line))
        return issues


class NoStringForSecretsRule(Rule):
    def __init__(self):
        super().__init__("JC011", "Avoid using String to store secrets (PINs/keys). Use byte[] and secure handling.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, field in ast.filter(jtree.FieldDeclaration):
            tname = getattr(field.type, "name", None)
            if tname == "String":
                for declarator in field.declarators or []:
                    vname = getattr(declarator, "name", None)
                    if _is_sensitive_name(vname):
                        line = getattr(field, "position", None)
                        line = line[0] if line else None
                        issues.append(Issue(self.rule_id, self.severity, f"Field '{vname}' typed as String may expose secrets", file_path, line))
        return issues


class NoStaticSecretByteArrayRule(Rule):
    def __init__(self):
        super().__init__("JC012", "Avoid storing secrets in static byte[] fields; prefer transient arrays or key objects.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, field in ast.filter(jtree.FieldDeclaration):
            mods = set(field.modifiers or [])
            if "static" in mods:
                try:
                    is_byte_array = getattr(field.type, "name", None) == "byte" and (field.type.dimensions and len(field.type.dimensions) >= 1)
                except Exception:
                    is_byte_array = False
                if is_byte_array:
                    for declarator in field.declarators or []:
                        vname = getattr(declarator, "name", None)
                        if _is_sensitive_name(vname):
                            line = getattr(field, "position", None)
                            line = line[0] if line else None
                            issues.append(Issue(self.rule_id, self.severity, f"Static byte[] field '{vname}' may hold secrets persistently", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class NoThreadUsageRule(Rule):
    def __init__(self):
        super().__init__("JC013", "Disallow Thread usage (no multi-threading on JavaCard)", "error")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, imp in ast.filter(jtree.Import):
            path = imp.path or ""
            if path.startswith("java.lang.Thread"):
                line = getattr(imp, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, f"Importing '{path}'", file_path, line))
        for _, ref in ast.filter(jtree.ReferenceType):
            name = ref.name if isinstance(ref.name, str) else None
            if name and name.split(".")[-1] == "Thread":
                line = getattr(ref, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Usage of Thread type", file_path, line))
        for _, cc in ast.filter(jtree.ClassCreator):
            tname = getattr(cc.type, "name", None)
            if isinstance(tname, str) and tname.split(".")[-1] == "Thread":
                line = getattr(cc, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Creation of Thread instance", file_path, line))
        return issues


class NoSystemGCRule(Rule):
    def __init__(self):
        super().__init__("JC014", "Disallow System.gc() on JavaCard", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            if qualifier == "System" and node.member == "gc":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Usage of System.gc()", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues


class AvoidArraysEqualsForSecretsRule(Rule):
    def __init__(self):
        super().__init__("JC015", "Avoid Arrays.equals for secret comparison; consider constant-time checks.", "warning")

    def apply(self, ast, file_path: str, source: str) -> List[Issue]:
        issues: List[Issue] = []
        for _, node in ast.filter(jtree.MethodInvocation):
            qualifier = node.qualifier or ""
            if qualifier == "Arrays" and node.member == "equals":
                line = getattr(node, "position", None)
                line = line[0] if line else None
                issues.append(Issue(self.rule_id, self.severity, "Arrays.equals() may leak timing information for secret data", file_path, line, RULE_FIX_RECOMMENDATIONS.get(self.rule_id)))
        return issues