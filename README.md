# DocScrub (PoC)

Local document sanitizer that produces a "safe to hand to AI" copy of a
document. Scans for PII, credentials/secrets, and internal infrastructure
identifiers, replaces them with **consistent, reversible tokens**, and emits
a findings report. Nothing leaves the machine.

## Why

MSPs (and everyone else) want LLM help on tickets, runbooks, and configs —
but those documents are full of client names, internal IPs, hostnames, UNC
paths, tenant IDs, and the occasional pasted password. DocScrub sits between
the document and the AI:

```
ticket.docx ──► docscrub sanitize ──► ticket_SANITIZED.docx ──► any LLM
                     │                                             │
                     ├─► findings_report.md (compliance artifact)  │
                     └─► mapping.json ──► docscrub rehydrate ◄─── AI reply
```

Because tokens are consistent (`<HOSTNAME_2>` is always the same server),
the AI's reasoning stays coherent, and `rehydrate` restores real values in
the AI's response afterward.

## Detection layers

1. **Presidio** (Microsoft's open-source PII framework) — emails, phones,
   credit cards, IBANs, and more via pattern recognizers.
2. **Custom regex rules** — private key blocks, AWS/GitHub/Slack/Google
   keys, JWTs, Azure AccountKeys, connection-string passwords, generic
   `api_key=` assignments, IPv4/IPv6 (classified internal vs public),
   MACs, GUIDs/tenant IDs, UNC paths, internal FQDNs (`.local`, `.corp`,
   …), and `XXX-DC01`-style hostname conventions.
3. **Heuristics + propagation** — context-driven person/org name detection,
   plus partial-leak prevention: once "Sarah Whitfield" is found, a later
   bare "Sarah" is redacted to the same token.

Severity model: `critical` (live credentials — rotate them), `high`
(internal infrastructure), `medium` (PII).

## Quick start (from source)

```bash
# Python 3.11+ required
pip install presidio-analyzer presidio-anonymizer python-docx pypdf flask
python -m spacy download en_core_web_sm   # optional but recommended (NER)

python -m docscrub gui        # opens the app at http://127.0.0.1:7860
```

The app auto-detects the best installed spaCy model
(`en_core_web_lg` → `md` → `sm`) and falls back to a pattern-only blank
pipeline if none is installed — it always works fully offline.

## Building installers

Binaries must be built on the target OS (PyInstaller doesn't cross-compile):

**macOS** — double-click `Build DocScrub.command` (or run
`./build_macos.sh`). Produces `DocScrub-<version>.dmg`: open it, drag
DocScrub into Applications. Done.

**Windows** — double-click `build_windows.bat`. Produces
`dist\DocScrub\DocScrub.exe` always; if Inno Setup 6 (free,
jrsoftware.org) is installed, it also compiles
`installer\DocScrub-Setup-<version>.exe` — a real installer with Start
Menu shortcut, optional desktop icon, and an uninstaller. Unsigned build:
SmartScreen will warn — "More info" → "Run anyway".

**Linux** — `pyinstaller docscrub.spec --noconfirm`.

The build scripts create their own venv, bundle the spaCy NER model, and
produce a self-contained app (~400–500 MB). The GUI opens in a native
window; the CLI works from a terminal against the same binary.

## CLI usage

```bash
python -m docscrub sanitize ticket.docx -o out/
# → ticket_SANITIZED.docx, findings_report.md, findings.json, mapping.json

python -m docscrub rehydrate ai_response.txt -m out/mapping.json
# → ai_response_REHYDRATED.txt

python -m docscrub gui [-p PORT] [--no-browser]
```

Supported inputs: `.docx`, `.xlsx`/`.xlsm` (formula-safe), `.eml`
(structure-preserving round-trip), `.msg` (Outlook → sanitized text),
`.pdf` (→ sanitized text), plus the whole plain-text family — `.txt`,
`.md`, `.log`, `.csv`, `.tsv`, `.json`, `.yaml`, `.xml`, `.html`, `.ini`,
`.conf`, `.toml`, `.ps1`, `.sh`, `.bat`, `.py`, `.sql`, and more.

## Demo

```bash
python make_demo.py                                   # fake MSP ticket
python -m docscrub sanitize demo/escalation_ticket_48213.docx -o demo/scrubbed
```

The demo ticket plants 25 unique sensitive values (credentials, internal
IPs, hostnames, UNC paths, tenant ID, SSN, JWT, names). The end-to-end
leak check confirms all are redacted.

## Known PoC limitations / production roadmap

- Person/org detection is heuristic (context words). Production: full NER
  model (`en_core_web_lg` or transformers) — the engine is already wired
  for it.
- Modified .docx paragraphs keep paragraph styling but collapse per-run
  (character-level) formatting within that paragraph.
- PDF output is extracted text, not a rebuilt PDF.
- `mapping.json` is plaintext; production should encrypt it (DPAPI/keyring)
  and add retention policy.
- No xlsx/pptx handlers yet; no GUI (drag-and-drop Electron/Tauri shell or
  a localhost web UI is the natural next step).
- Entities spanning two paragraphs aren't caught (per-paragraph scanning).
