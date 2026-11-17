"""Pre-release check: AMEP must not credit any AI product or tool as an author or contributor.

Reports every mention of AI products and tool vendors in the repository's text files, split into:
  - ATTRIBUTION: wording that credits authorship (always a release blocker), and
  - MENTION: other mentions (for example, a host listed in a compatibility table, or a protected
    configuration path), for a person to review.
Read-only. Run from the repo root: python3 -I tools/attribution_check.py
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SKIP_DIRS = {".git", ".natsar-trash", "node_modules", "__pycache__"}
EXTS = (".md", ".py", ".mjs", ".js", ".json", ".cddl", ".cff", ".html", ".txt")
NAMES = re.compile(r"codex|openai|claude|anthropic|chatgpt|gpt-\d|copilot|gemini", re.I)
CREDIT = re.compile(r"co-authored|generated (by|with)|written (by|with)|authored (by|with)|assisted by|created (by|with)|\bAI[- ]generated", re.I)


def main():
    attribution, mentions = [], {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if not (f.endswith(EXTS) or f in ("NOTICE",)):
                continue
            path = os.path.relpath(os.path.join(dirpath, f), ROOT)
            if path == os.path.join("tools", "attribution_check.py"):
                continue
            for n, line in enumerate(open(os.path.join(dirpath, f), encoding="utf-8", errors="replace"), 1):
                if NAMES.search(line):
                    if CREDIT.search(line):
                        attribution.append(f"{path}:{n}: {line.strip()[:140]}")
                    else:
                        for m in NAMES.findall(line):
                            mentions.setdefault(path, set()).add(m.lower())
    print("ATTRIBUTION (must be empty):")
    print("\n".join("  " + a for a in attribution) or "  none")
    print("MENTIONS (review):")
    for path in sorted(mentions):
        print(f"  {path}: {', '.join(sorted(mentions[path]))}")
    return 1 if attribution else 0


if __name__ == "__main__":
    sys.exit(main())
