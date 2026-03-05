#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()

def iter_all_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            for root, _, files in os.walk(p):
                for name in files:
                    out.append(Path(root) / name)
        elif p.is_file():
            out.append(p)
    return out

def cmd_ping(args: argparse.Namespace) -> int:
    emit({"type": "hello", "engine": "juicesuite_engine", "version": "0.1", "ts": time.time()})
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    inputs = [Path(x).expanduser().resolve() for x in args.input]
    emit({"type": "start", "mode": "scan", "inputs": [str(p) for p in inputs], "ts": time.time()})

    files = iter_all_files(inputs)
    total = len(files)
    emit({"type": "progress", "phase": "enumerate", "total": total, "done": 0})

    # Simple “analysis” placeholder
    # (Later: carving, sqlite parse, NSFW, EXIF, dedupe, report)
    for i, f in enumerate(files, start=1):
        if i == 1 or i % 200 == 0 or i == total:
            emit({"type": "progress", "phase": "scan", "total": total, "done": i, "current": str(f)})

        # Emit a “found” event for anything that looks like media
        ext = f.suffix.lower()
        if ext in {".jpg",".jpeg",".png",".gif",".webp",".heic",".heif",".tif",".tiff",".bmp",".mp4",".mov",".m4v",".mkv",".avi",".webm"}:
            emit({"type": "found", "kind": "media", "path": str(f), "ext": ext})

    # Write an output JSON if requested
    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_obj = {
            "engine": "juicesuite_engine",
            "version": "0.1",
            "inputs": [str(p) for p in inputs],
            "total_files": total,
            "ts": time.time(),
        }
        out_path.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")
        emit({"type": "report", "path": str(out_path)})

    emit({"type": "done", "total_files": total, "ts": time.time()})
    return 0

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="juicesuite_engine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ping = sub.add_parser("ping", help="Sanity check")
    p_ping.set_defaults(fn=cmd_ping)

    p_scan = sub.add_parser("scan", help="Scan files/folders (placeholder)")
    p_scan.add_argument("--input", nargs="+", required=True, help="Files/folders to scan")
    p_scan.add_argument("--out", default=None, help="Optional JSON summary output path")
    p_scan.set_defaults(fn=cmd_scan)

    return ap

def main(argv: list[str]) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return int(args.fn(args))

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
