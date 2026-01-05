# JavaCardChecker

JavaCardChecker is a command-line static analyzer for Java `.java` files, focused on JavaCard restrictions. It parses source code and reports rule violations similar to tools like cppcheck.

## Features
- Fast CLI to analyze a file or an entire directory of `.java` files
- Text and JSON output formats for human and machine consumption
- Severity filtering to show only `error` or `warning`
- Extensible rule engine
- Actionable fix recommendations included in both text and JSON outputs
- Expanded ruleset covering applet lifecycle, APDU handling, and smartcard security aligned with JavaCard and common ETSI/3GPP practices

## Implemented Rules
- Core platform restrictions:
  - JC001: Disallow usage of `float`/`double` primitives and wrappers `Float`/`Double`
  - JC002: Disallow `java.io` imports
  - JC003: Disallow reflection APIs (`java.lang.reflect`, `Class.forName`, `newInstance`)
  - JC004: Warn on `System.out`/`System.err` usage
  - JC005: Disallow `finalize()` method
  - JC006: Disallow `synchronized` keyword and synchronized blocks
- Applet lifecycle and structure:
  - JC007: Require classes that look like applets to extend `javacard.framework.Applet`
  - JC008: Enforce canonical `install(byte[] bArray, short bOffset, byte bLength)` signature
  - JC009: Enforce canonical `process(APDU apdu)` signature
- Security and platform best practices:
  - JC010: Prefer `ISOException.throwIt(...)` over generic exceptions
  - JC011: Avoid using `String` for secrets (prefer `byte[]`)
  - JC012: Avoid static secret `byte[]` fields (prefer transient arrays or key objects)
  - JC013: Disallow `Thread` usage
  - JC014: Disallow `System.gc()`
  - JC015: Avoid `Arrays.equals()` for secret comparisons (timing leak risk)
- APDU handling, ETSI/3GPP smartcard practices, and crypto robustness:
  - JC016: Require `apdu.receiveBytes()` or `apdu.getBuffer()` usage only after `apdu.setIncomingAndReceive()`
  - JC017: Prefer `JCSystem.makeTransientByteArray()` for temporary buffers
  - JC018: Require `Applet.register()` call during installation
  - JC019: Disallow forbidden non-JavaCard imports (desktop/server-only packages)
  - JC020: Disallow `System.currentTimeMillis()`/`nanoTime()` on JavaCard
  - JC021: Require `apdu.setIncomingAndReceive()` before `receiveBytes()` or `getIncomingLength()` in `process`
  - JC022: Warn if `switch` in `process(APDU)` lacks a `default` branch
  - JC023: Warn on persistent class-level `byte[]` fields (suggest transient arrays)
  - JC024: Encourage `OwnerPIN` for PIN management
  - JC025: Disallow `java.util.Random`
  - JC026: Disallow `java.math.BigInteger`
  - JC027: Warn if applet does not handle GPO (0xA8) or READ RECORD (0xB2) (EMV compliance)
  - JC028: Prefer ISO7816 constants over hardcoded status words

Parse errors or invalid inputs are reported as a warning with rule ID `JC000`.

## Requirements
- Windows (PowerShell) or any platform with Python 3.x installed
- Python dependencies: `javalang`

## Installation

### Option 1: Install as a package (Recommended)
You can install `jcchecker` as a Python package, which makes the `jcchecker` command available globally (or in your virtualenv).

```powershell
# In the project root
pip install .
```

Then you can use it directly:
```powershell
jcchecker samples/BadApplet.java
```

### Option 2: Run from source
1. Open a terminal in the project folder:
   ```powershell
   cd ..\JavaCardChecker
   ```
2. Create a virtual environment (first time only):
   ```powershell
   python -m venv .venv
   ```
3. Install dependencies:
   ```powershell
   .venv\Scripts\pip install -r requirements.txt
   ```
4. Run via `main.py`:
   ```powershell
   .venv\Scripts\python main.py <path-to-java-file>
   ```

## Usage
Run the analyzer on a file or directory:
```powershell
jcchecker <path-to-java-file-or-directory>
# OR
python main.py <path-to-java-file-or-directory>
```

Options:
- `--format text|json`  (default: `text`)
- `--severity all|error|warning`  (default: `all`)

### Examples
- Analyze the provided sample:
  ```powershell
  .venv\Scripts\python main.py samples --format text
  ```
- Analyze your project directory (text output):
  ```powershell
  .venv\Scripts\python main.py [target folder] --format text
  ```
- JSON output filtering errors only:
  ```powershell
  .venv\Scripts\python main.py [target folder] --format json --severity error
  ```

### Optional: Activate the virtual environment
If you prefer to use `python` directly instead of the full path:
```powershell
.venv\Scripts\Activate.ps1
python main.py samples --format text
```
If running `Activate.ps1` is blocked by execution policy, continue using the full path `.venv\Scripts\python`.

## Output Format
- Text:
  ```
  path\to\File.java:line: severity RULE_ID: message
    fix: short actionable recommendation
  ```
- JSON:
  ```json
  [
    {
      "rule_id": "JC001",
      "severity": "error",
      "message": "Usage of primitive type 'double'",
      "file": "samples/BadApplet.java",
      "line": 7,
      "recommendation": "Replace float/double with byte/short; use fixed-point (scaled short) for decimals."
    }
  ]
  ```

## Project Structure
- CLI entry point: `main.py`
- Analyzer and rule engine: `jcchecker/`
  - `engine.py` — issue model and rule application (includes recommendation support)
  - `analyzer.py` — directory scanning and parsing
  - `rules.py` — core JavaCard rules and default ruleset
  - `extra_rules.py` — ETSI/3GPP and security-focused rules integrated into the default ruleset
  - `recommendations.py` — centralized map of fix tips keyed by rule ID
- Sample Java file: `samples/BadApplet.java`
- Dependencies: `requirements.txt`

## Extending Rules
1. Open `jcchecker/rules.py` (for core rules) or `jcchecker/extra_rules.py` (for domain-specific rules)
2. Create a new class inheriting from `Rule` and implement `apply(self, ast, file_path, source)`
3. Add your rule to `get_default_rules()` (core) or return it from `get_additional_rules()` in `extra_rules.py`
4. Optionally, add a fix hint to `jcchecker/recommendations.py` under the corresponding rule ID

Example skeleton:
```python
from .engine import Rule, Issue
from javalang import tree as jtree

class MyCustomRule(Rule):
    def __init__(self):
        super().__init__("JC999", "Describe your rule", "warning")

    def apply(self, ast, file_path, source):
        issues = []
        # Inspect AST nodes via ast.filter(jtree.SomeNodeType)
        return issues
```

## Notes
- The parser is powered by `javalang`. Severe syntax errors are surfaced as `JC000` warnings to avoid crashing.
- Line numbers are best-effort based on AST node positions.
- Recommendations are short tips intended to guide remediation; adapt to your coding standards or issuer profiles as needed.

## License
MIT License

Copyright (c) 2026 JavaCardChecker Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.