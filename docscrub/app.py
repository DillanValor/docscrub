"""DocScrub local web app.

Runs a Flask server bound to 127.0.0.1 only — the browser UI is the GUI.
No external calls, no telemetry. Each sanitize job gets a workspace under
the OS temp dir; jobs are kept in memory for the life of the process.
"""

import csv
import io
import json
import secrets
import tempfile
import threading
import webbrowser
from pathlib import Path

from flask import Flask, jsonify, request, send_file, send_from_directory

from .engine import Scrubber, rehydrate
from .handlers import sanitize_file, HANDLERS
from .report import build_report, _mask, friendly_label, SEVERITY_ORDER

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

JOBS = {}          # job_id -> {dir, out_path, report_path, mapping, findings}
_SCRUBBER_LOCK = threading.Lock()
_MODEL_INFO = {"name": None, "tier": None}

# Session memory: every value ever redacted in this app session. A secret
# that comes back WITHOUT its original context (an AI response saying
# "rotate the key fgt_…") is still recognized on re-sanitize. Lives only
# in process memory — same privacy model as the mappings themselves.
_SESSION_KNOWN = {}   # value -> entity_type


def _new_scrubber():
    scrubber = Scrubber()
    _MODEL_INFO.update(name=scrubber.model_name, tier=scrubber.model_tier)
    for value, etype in _SESSION_KNOWN.items():
        scrubber.add_known_value(etype, value)
    return scrubber


def _remember(mapping):
    for info in mapping.values():
        _SESSION_KNOWN.setdefault(info["value"], info["type"])


@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/api/info")
def info():
    from . import __version__
    return jsonify({
        "version": __version__,
        "model": _MODEL_INFO,
        "supported": sorted(HANDLERS.keys()),
    })


@app.post("/api/sanitize")
def api_sanitize():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    up = request.files["file"]
    ext = Path(up.filename).suffix.lower()
    if ext not in HANDLERS:
        return jsonify({"error": f"unsupported file type '{ext}' — "
                                 f"supported: {', '.join(sorted(HANDLERS))}"}), 400

    job_id = secrets.token_hex(8)
    job_dir = Path(tempfile.mkdtemp(prefix=f"docscrub_{job_id}_"))
    in_path = job_dir / Path(up.filename).name
    up.save(in_path)

    with _SCRUBBER_LOCK:  # one scan at a time keeps memory sane
        scrubber = _new_scrubber()
        try:
            out_path, findings = sanitize_file(scrubber, in_path, job_dir / "out")
        except Exception as exc:  # corrupt file, password-protected, etc.
            return jsonify({"error": f"could not process file: {exc}"}), 422

    return _finish_job(job_id, job_dir, up.filename, out_path,
                       findings, scrubber)


@app.post("/api/sanitize-text")
def api_sanitize_text():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "no text provided"}), 400

    job_id = secrets.token_hex(8)
    job_dir = Path(tempfile.mkdtemp(prefix=f"docscrub_{job_id}_"))
    (job_dir / "out").mkdir(parents=True, exist_ok=True)

    with _SCRUBBER_LOCK:
        scrubber = _new_scrubber()
        sanitized, findings = scrubber.sanitize_text(text)

    out_path = job_dir / "out" / "pasted_text_SANITIZED.txt"
    out_path.write_text(sanitized, encoding="utf-8")
    return _finish_job(job_id, job_dir, "pasted_text.txt", out_path,
                       findings, scrubber, extra={"sanitized_text": sanitized})


def _finish_job(job_id, job_dir, input_name, out_path, findings, scrubber,
                extra=None):
    mapping = scrubber.mapping()
    _remember(mapping)
    report_md = build_report(input_name, out_path.name, findings, mapping)
    report_path = job_dir / "out" / "findings_report.md"
    report_path.write_text(report_md, encoding="utf-8")
    mapping_path = job_dir / "out" / "mapping.json"
    mapping_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")

    unique = {}
    for f in findings:
        unique.setdefault(f.token, f)
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    items = [
        {
            "token": tok,
            "type": f.entity_type,
            "label": friendly_label(f.entity_type),
            "severity": f.severity,
            "masked_value": _mask(f.text, f.severity),
            "layer": f.layer,
            "score": round(f.score, 2),
            "occurrences": sum(1 for x in findings if x.token == tok),
        }
        for tok, f in unique.items()
    ]
    # Legend order: grouped by type, then token number — matches how a
    # reader scans the sanitized doc. Findings order: severity first.
    items.sort(key=lambda i: (i["type"], len(i["token"]), i["token"]))

    JOBS[job_id] = {
        "dir": job_dir, "out_path": out_path,
        "report_path": report_path, "mapping_path": mapping_path,
        "mapping": mapping, "items": items, "input_name": input_name,
    }

    payload = {
        "job_id": job_id,
        "input_name": input_name,
        "output_name": out_path.name,
        "total_redactions": len(findings),
        "unique_values": len(unique),
        "severity_counts": sev_counts,
        "model": dict(_MODEL_INFO),
        "items": items,
    }
    if extra:
        payload.update(extra)
    return jsonify(payload)


def _csv_bytes(rows, header):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")  # BOM: Excel-friendly


def _artifact_bytes(job_id, which):
    """(bytes, filename) for any downloadable artifact, or (None, None).

    Single source of truth used by BOTH the browser download endpoint and
    the native-window save dialog bridge."""
    job = JOBS.get(job_id)
    if not job:
        return None, None
    stem = Path(job["input_name"]).stem
    if which == "legend":
        rows = [(i["token"], i["label"], i["masked_value"], i["occurrences"])
                for i in job["items"]]
        return _csv_bytes(rows, ["token", "meaning", "value_masked",
                                 "occurrences"]), f"{stem}_legend.csv"
    if which == "findings":
        items = sorted(job["items"],
                       key=lambda i: (SEVERITY_ORDER[i["severity"]], i["token"]))
        rows = [(i["token"], i["type"], i["label"], i["severity"], i["layer"],
                 i["score"], i["masked_value"], i["occurrences"])
                for i in items]
        return _csv_bytes(rows, ["token", "type", "meaning", "severity",
                                 "layer", "score", "value_masked",
                                 "occurrences"]), f"{stem}_findings.csv"
    path = {"sanitized": job["out_path"],
            "report": job["report_path"],
            "mapping": job["mapping_path"]}.get(which)
    if path is None:
        return None, None
    return Path(path).read_bytes(), Path(path).name


@app.get("/api/download/<job_id>/<which>")
def api_download(job_id, which):
    data, filename = _artifact_bytes(job_id, which)
    if data is None:
        return jsonify({"error": "unknown job or artifact"}), 404
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=filename)


@app.get("/api/jobs")
def api_jobs():
    return jsonify([
        {"job_id": jid, "input_name": j["input_name"],
         "tokens": len(j["mapping"])}
        for jid, j in JOBS.items()
    ])


@app.post("/api/rehydrate")
def api_rehydrate():
    import re as _re

    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "no text provided"}), 400

    mapping = None
    if data.get("job_id") and data["job_id"] in JOBS:
        mapping = JOBS[data["job_id"]]["mapping"]
    elif data.get("mapping"):
        mapping = data["mapping"]
    if mapping is None:
        return jsonify({"error": "no mapping available — sanitize a document "
                                 "first or paste a mapping.json"}), 400

    # Be explicit about what did and didn't resolve — silent partial
    # rehydration against the wrong document's mapping is a footgun.
    tokens_in = set(_re.findall(r"<[A-Z][A-Z0-9_]*_\d+>", text))
    unresolved = sorted(t for t in tokens_in if t not in mapping)
    return jsonify({
        "text": rehydrate(text, mapping),
        "tokens_found": len(tokens_in),
        "tokens_restored": len(tokens_in) - len(unresolved),
        "unresolved": unresolved,
    })


def _wait_for_server(port, timeout=15.0):
    import socket
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def run_app(port=7860, open_browser=True, native=True):
    """Launch DocScrub.

    native=True: try a real desktop window (pywebview → WKWebView on macOS,
    Edge WebView2 on Windows). Closing the window quits the app — proper
    app behavior. Falls back to the browser if pywebview isn't available.
    """
    url = f"http://127.0.0.1:{port}"

    if native:
        try:
            import webview
        except ImportError:
            webview = None
        if webview is not None:
            threading.Thread(
                target=lambda: app.run(host="127.0.0.1", port=port,
                                       debug=False, use_reloader=False),
                daemon=True,
            ).start()
            if not _wait_for_server(port):
                raise RuntimeError(f"server failed to start on port {port}")

            class _NativeApi:
                """JS bridge: native save dialog for downloads.

                WKWebView/WebView2 don't handle browser-style downloads —
                links either dead-end or navigate the app window away. The
                UI detects window.pywebview and calls this instead."""

                def save_artifact(self, job_id, which):
                    data, filename = _artifact_bytes(job_id, which)
                    if data is None:
                        return {"ok": False, "error": "unknown artifact"}
                    win = webview.windows[0]
                    try:
                        dest = win.create_file_dialog(
                            webview.SAVE_DIALOG, save_filename=filename)
                    except Exception as exc:
                        return {"ok": False, "error": str(exc)}
                    if not dest:
                        return {"ok": False, "error": "cancelled"}
                    if isinstance(dest, (list, tuple)):
                        dest = dest[0]
                    Path(dest).write_bytes(data)
                    return {"ok": True, "path": str(dest)}

            try:  # belt & suspenders on pywebview ≥4.1
                webview.settings["ALLOW_DOWNLOADS"] = True
            except Exception:
                pass
            webview.create_window(
                "DocScrub", url, width=1150, height=860,
                min_size=(920, 640), js_api=_NativeApi())
            webview.start()   # blocks until the window closes
            return

    print(f"DocScrub running at {url}  (Ctrl+C to quit — everything stays local)")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False)
