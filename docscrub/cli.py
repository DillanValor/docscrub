"""DocScrub CLI.

  python -m docscrub sanitize <file> [-o OUTDIR]
      → <name>_SANITIZED.<ext>, findings_report.md, mapping.json

  python -m docscrub rehydrate <ai_output.txt> -m mapping.json [-o OUTFILE]
      → tokens replaced with original values
"""

import argparse
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

def cmd_sanitize(args):
    from .engine import Scrubber
    from .handlers import sanitize_file
    from .report import build_report

    out_dir = Path(args.output or Path(args.file).parent / "scrubbed")
    scrubber = Scrubber()
    print(f"NLP model     : {scrubber.model_name} ({scrubber.model_tier})")

    out_path, findings = sanitize_file(scrubber, args.file, out_dir)

    mapping_path = out_dir / "mapping.json"
    scrubber.save_mapping(mapping_path)

    report_md = build_report(args.file, out_path, findings, scrubber.mapping())
    report_path = out_dir / "findings_report.md"
    report_path.write_text(report_md, encoding="utf-8")

    findings_json = out_dir / "findings.json"
    findings_json.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")

    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")
    print(f"Sanitized     : {out_path}")
    print(f"Report        : {report_path}")
    print(f"Mapping (keep private!) : {mapping_path}")
    print(f"Redactions    : {len(findings)} total — "
          f"{crit} critical, {high} high, {med} medium")


def cmd_rehydrate(args):
    from .engine import rehydrate

    mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8"))
    text = Path(args.file).read_text(encoding="utf-8")
    restored = rehydrate(text, mapping)
    out = Path(args.output or Path(args.file).with_name(
        Path(args.file).stem + "_REHYDRATED" + Path(args.file).suffix))
    out.write_text(restored, encoding="utf-8")
    print(f"Rehydrated    : {out}")


def cmd_gui(args):
    from .app import run_app
    run_app(port=args.port, open_browser=not args.no_browser,
            native=not (args.browser or args.no_browser))


def main(argv=None):
    p = argparse.ArgumentParser(prog="docscrub",
                                description="Local document sanitizer for AI-safe sharing")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sanitize", help="scan + tokenize a document")
    ps.add_argument("file")
    ps.add_argument("-o", "--output", help="output directory (default: ./scrubbed)")
    ps.set_defaults(func=cmd_sanitize)

    pr = sub.add_parser("rehydrate", help="restore original values in AI output")
    pr.add_argument("file")
    pr.add_argument("-m", "--mapping", required=True)
    pr.add_argument("-o", "--output")
    pr.set_defaults(func=cmd_rehydrate)

    pg = sub.add_parser("gui", help="launch the app (native window)")
    pg.add_argument("-p", "--port", type=int, default=7860)
    pg.add_argument("--browser", action="store_true",
                    help="open in the default browser instead of a native window")
    pg.add_argument("--no-browser", action="store_true",
                    help="server only; don't open any UI")
    pg.set_defaults(func=cmd_gui)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
