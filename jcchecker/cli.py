import argparse
import json
import sys
from typing import List

from .analyzer import analyze_path


def main():
    parser = argparse.ArgumentParser(
        description="JavaCard static analyzer (like cppcheck, for .java files)")
    parser.add_argument("path", help="Path to a Java file or directory")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format")
    parser.add_argument("--severity", choices=["all", "error", "warning"], default="all",
                        help="Filter by severity")

    args = parser.parse_args()

    try:
        issues = analyze_path(args.path)
    except Exception as e:
        print(f"Error analyzing path: {e}", file=sys.stderr)
        sys.exit(1)

    # Severity filtering
    if args.severity != "all":
        issues = [i for i in issues if i.severity == args.severity]

    if args.format == "json":
        print(json.dumps([i.to_dict() for i in issues], indent=2))
    else:
        for i in issues:
            print(i.format_text())


if __name__ == "__main__":
    main()
