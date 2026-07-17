# Project Notes — DocScrub (for future valorops.dev blog post)

*Running log kept by Claude per Dillan's workflow: track the project as we
build, draft blog content at the end.*

## 2026-07-17 — Session 1: idea → working PoC

**The idea (Dillan):** MSPs feed tickets/docs to LLMs constantly; biggest
concern is data control. Build a tool that scans an uploaded document for
sensitive info (IPs, encryption keys, PII), sanitizes it *locally*, and
returns a "ready to safely hand to AI" copy.

**Landscape research:** building blocks exist (Microsoft Presidio for PII,
gitleaks/trufflehog rule sets for secrets, pii-redactor for the
tokenize/rehydrate pattern), but they're developer libraries or cloud APIs.
The packaged local-first "upload doc → sanitized doc + report" experience
for non-developers is the gap. Differentiators identified: reversible
consistent tokenization, docx format fidelity, findings report as
compliance artifact, infra-aware detection (RFC1918, hostnames, UNC paths,
tenant IDs) that generic PII tools ignore.

**Built:** Python package `docscrub` — 3-layer detection engine
(Presidio + custom regex + heuristics), consistent reversible tokenization,
docx/pdf/txt handlers, markdown findings report with severity model,
CLI with `sanitize` and `rehydrate` commands.

**War stories worth blogging:**
- Sandbox proxy blocked GitHub/HF model downloads → ran Presidio on a blank
  spaCy pipeline; pattern recognizers don't need the NER model. Modular
  design meant the ML layer is a config swap later.
- Presidio's built-in US_SSN recognizer missed a bare `078-05-1120` (needs
  context); custom regex layer covers it.
- `re.IGNORECASE` on the name heuristic made `[A-Z][a-z]+` match anything —
  "User reports VPN" got redacted as a person. Fix: Python 3.11 scoped
  inline flags `(?-i:...)` to keep the name group case-sensitive.
- Partial-leak problem: "Sarah Whitfield" caught, later solo "Sarah"
  leaked. Added name-part propagation mapping to the same token.
- Python's `ipaddress` counts TEST-NET ranges (203.0.113.x) as private —
  matters when picking demo data.

**Demo result:** fake MSP escalation ticket with 25 unique planted values
(creds, internal IPs, hostnames, UNC path, tenant GUID, SSN, JWT, PII) —
29 redactions, zero leaks on the check list, rehydration round-trip clean.

**Next steps (not started):** GUI (drag-drop, localhost web UI), xlsx/pptx
handlers, rebuilt sanitized PDFs, encrypted mapping store, full NER model,
config profiles per client, maybe an M365/Purview integration angle.

**Testing plan (Dillan):** Mac for quick functional test (needs Python
3.11+ for scoped regex flags; install en_core_web_lg for full NER).
Windows desktop for the real validation — MSP/docx/UNC world is
Windows-native, plus the Intune/Defender-managed box makes the demo doc
(SSNs, card-shaped numbers, API keys) an accidental DLP test payload.
Blog angle: sanitizer tool coexisting with endpoint DLP.

## 2026-07-17 — Session 2: PoC → compiled prototype app

**Built:** local web GUI (Flask on 127.0.0.1, single-file dark UI — drag &
drop sanitize, severity stat tiles, findings table with masked values,
download buttons, rehydrate tab). `docscrub gui` command. Engine upgrades:
auto model resolution (en_core_web_lg → md → sm → blank fallback, frozen-app
safe via importlib), shared analyzer per process (model loads once), NER
entities (PERSON/LOCATION) wired into Presidio layer when a real model is
present. PyInstaller spec + one-command build scripts for macOS/Windows.

**War stories (session 2):**
- Can't cross-compile: sandbox is Linux, so shipped build scripts instead
  of a Mac binary; validated the spec by building/running the Linux binary.
- Frozen-build validation caught two real bugs: python-docx's XML templates
  weren't collected (crash on docx with headers/footers), and Presidio's
  URL recognizer (tldextract) phones home for the public-suffix list at
  first use — patched to bundled-snapshot-only. Great blog beat: "my
  no-network app was making a network call I never wrote."
- Verified frozen CLI + GUI end-to-end on the demo ticket (29 redactions,
  same results as source run). One-dir bundle ~430MB on Linux.

## 2026-07-17 — Session 3: first field test (Dillan's Mac)

Dillan built the app on his first-ever Mac via build_macos.sh (after the
classic pip-not-on-PATH / no-Homebrew onboarding; python.org installer
route worked). Ran the demo ticket through the browser GUI.

**Result: zero leaks — all 25 planted values redacted.** Bundled
en_core_web_sm NER active. BUT the small model added 4 false positives:
"Technician" → NRP, "Purge SSN" → PERSON, "Backup NAS" (table label) →
PERSON, and Azure "AccountName" label swallowed into an NRP span.
Detection stayed safe; precision suffered — over-redaction degrades what
the AI can usefully do with the doc.

**Fix shipped:** dropped NRP entity entirely (noise for MSP docs), added
name-shape post-filter for ML PERSON hits (2–4 words, each name-shaped or
a particle like "van"; single words handled by name-part propagation),
digit/acronym filter for LOCATION. Unit-tested against the exact false
positives from the field test. Blog beat: patterns caught everything on
this doc with zero FPs; the ML layer added recall insurance but needed a
precision leash — layered detection means post-filters per layer.

## 2026-07-17 — Session 4: field test #2 (harder doc, blind-graded)

Test doc: fake network migration runbook. Unlabeled mid-sentence names
(NER stress), 6 secret formats, IPv6 ULA with :: compression, spaced
credit card, netmask + version/KB/RFC negatives section.

**NER win:** all four unlabeled people caught on Dillan's Mac build —
exactly what the heuristic layer can't do.

**Leaks found (graded against answer key):** BVL-SW01 (hostname suffix
list lacked SW → added generic PREFIX-ROLE## rule), fd00:44:0:99::1
(IPv6 regex couldn't handle :: compression → loosened candidate regex,
ipaddress validates), 4532 7597 3454 8801 (Presidio requires valid Luhn;
test number wasn't → added card-shaped regex without checksum: for a
sanitizer, a mistyped card is still worth redacting), client org
"Bayview Logistics" unlabeled (added migrate/onboard context words; NER
ORG entity noted as a roadmap item — sm model too noisy for it).

**Over-redactions fixed:** doc title "Network Migration Runbook" → PERSON
(added tech-word stoplist to name-shape filter), 255.255.255.0 netmask →
INTERNAL_IP (excluded reserved/multicast in IP classifier), then Presidio
PHONE grabbed the netmask instead (added IP-shape guard to Presidio
layer — fixing one layer exposed the next; layered detection needs
layered guards). Also: "Jr." suffix absorption for PERSON spans, secret
values no longer swallow sentence periods.

Regression: doc #1 still 29/29, doc #2 clean on both leak and must-keep
checks. Known remaining gap: client public domains (bayviewlog.com) are
not redacted — needs a per-client config/wordlist feature.

## 2026-07-17 — Session 5: GUI iteration from field feedback (v0.2.0)

Dillan's first UX call after real use: the detail table under the scan was
the wrong thing to lead with — a reader of the sanitized doc needs a fast
"what does each placeholder mean" lookup, not forensic detail. Restructured:
**Placeholder legend** (token → plain-English meaning → masked preview,
severity color bar, grouped by type) sits directly under the scan tiles;
full findings (severity/layer/score sort) moved to their own tab with a
count badge. Both exportable as CSV (UTF-8 BOM for Excel) — legend.csv and
findings.csv, both masked so they're safe to attach to tickets/compliance
records. Added a plain-English label map for all entity types.

## 2026-07-17 — Session 6: real app packaging (DocScrub.app)

Made it an actual Mac app: pywebview native window (WKWebView) replaces
the browser tab — closing the window quits the app, falls back to browser
mode if pywebview is missing (`gui --browser` forces it, `--no-browser`
is server-only). PIL-drawn icon (document + redaction bars + sparkle) as
.icns/.ico/png. PyInstaller BUNDLE step produces DocScrub.app with proper
Info.plist (bundle id dev.valorops.docscrub); console flag now
Windows-only so the Mac app is windowed while Win CLI keeps stdout.
build_macos.sh zips the .app with drag-to-/Applications instructions.
Linux spec validation + frozen regression: both test docs pass.

## 2026-07-17 — Session 7: paste-text mode (v0.3.0, Dillan's feature call)

Dillan's insight: the #1 real workflow isn't file upload, it's copy/paste —
a tech pasting a log snippet or email into an AI chat. Added Document /
Paste-text toggle on the Sanitize tab: paste → sanitized text in a
copy-button box (clipboard API with execCommand fallback for embedded
webviews) → same tiles/legend/downloads under it, rehydrate gets a copy
button too. New /api/sanitize-text endpoint reuses the whole job pipeline
via a _finish_job refactor. Bug found by the test paste: connection-string
password rule swallowed sentence periods (same class of bug as the generic
secret rule — pattern-family bugs recur across siblings; worth a blog line).

## 2026-07-17 — Session 8: format expansion (v0.4.0, Dillan's pick)

Dillan picked "more formats" from the roadmap. Added: **xlsx/xlsm**
(openpyxl, per-cell sanitize, formulas untouched, styling preserved;
charts/images caveat), **eml** (full round-trip — address headers,
subject, and text bodies sanitized in place; attachments pass through
unscanned), **msg** (Outlook OLE — extract-msg wouldn't build in the
sandbox, so hand-rolled MAPI property stream extraction with pure-python
olefile → sanitized text), and registered ~20 plain-text extensions
(json/yaml/xml/ini/ps1/sh/sql/…) through the txt handler.

Test result note: bare names in spreadsheet cells have no context words —
pattern layer can't catch them, NER should (verify on Mac build). Roadmap
idea from this: column-header-aware detection (header "Display Name" →
treat column as PERSON). Frozen Linux build revalidated on both new
formats.

## 2026-07-17 — Session 9: native-window download bug (v0.4.1, field report)

Dillan hit it immediately on the .app build: download buttons dead, and
the Legend CSV *navigated* the WKWebView to raw CSV text with no way back.
Root cause: native webviews (WKWebView/WebView2) don't implement
browser-style downloads — my browser-tested links were never going to
work in the packaged app. Fix: pywebview js_api bridge — the UI detects
window.pywebview and routes downloads through a native macOS save dialog;
artifact generation refactored to a single _artifact_bytes() source of
truth shared by the browser endpoint and the native bridge. Buttons show
✓ Saved / ✗ Failed feedback. Browser mode regression-tested (all five
artifacts download with correct content types). Blog beat: "works in the
browser" ≠ "works in the app wrapper" — test the packaged thing.

## 2026-07-17 — Session 10: structure-aware detection (v0.4.2, field test #3)

Mac results on the three formats: docx perfect. But xlsx + eml exposed
the small NER model coin-flipping: "Sarah Whitfield" caught in a bare
cell, "Marcus Reyes" missed in both a cell and the To: header; greeting
"Marcus" mislabeled LOCATION. Key insight: don't need a better model
where STRUCTURE already proves the answer — an address header's display
name IS a person; a "Display Name" column holds names.

Built: known-values engine API (add_known_value → exact-match detection
at priority 6, parts propagate like any name) + structure hooks: eml
registers display names from all address headers via getaddresses; xlsx
registers cells under name-ish column headers (name/user/owner/contact/
technician/…). Verified in the sandbox with NO NER model: everything the
sm model missed is now caught deterministically, consistent tokens across
header/greeting/signature. Blog beat: layered detection's best layer is
document structure, not ML. Regression: doc #1 still 29/29.

## 2026-07-17 — Session 11: field test #4 (v0.4.3)

All three docx results from the Mac: zero leaks, negatives intact. Two
issues surfaced. (1) eml greeting still LOCATION on the Mac build — NER
tags bare "Marcus" as LOCATION at priority 4; part propagation ran
post-resolution at priority 2 and never displaces findings. Couldn't
repro in the sandbox (no NER) — environment asymmetry strikes again.
Fix: known name PARTS now detected pre-resolution at priority 5 (full
values 6), so structural knowledge outranks NER noise; stopword guard on
part registration. (2) Dillan's partial-rehydration report: rehydrate
silently used the mapping from the MOST RECENT scan — with several scans
in a session, tokens from an older doc's legend part-match by luck.
Fix: mapping source dropdown on the Rehydrate tab (/api/jobs) + response
now reports tokens_found/restored and lists unresolved tokens with a
visible warning ("is this the right source document?"). Silent partial
success upgraded to loud explicit state — the UX principle of the day.

## 2026-07-17 — Session 12: the round-trip leak (v0.5.0 — Dillan's best find)

Dillan round-tripped it: sanitize → AI → rehydrate → re-sanitize the
rehydrated text. Second pass LEAKED the API key and client org name.
Root cause: context-dependent detection — the key was only caught via
its `api_key =` assignment; the AI's paraphrase ("rotate the key
fgt_…") strips the context. **AI responses paraphrase; paraphrase kills
context rules.** Best insight of the project.

Three fixes: (1) context-free POSSIBLE_SECRET rule — bare tokens ≥16
chars with mixed case + ≥2 digits (gitleaks-style), validated in code,
below specific key rules in priority; (2) session memory — every value
ever mapped in the app session re-registers as a known value in later
scans, so round-trips are sealed deterministically; (3) org-by-suffix
heuristic (… Dental Group / … Logistics) with tech-word stoplist so
"Network Security Group" doesn't trip. Verified: exact round-trip now
returns fully tokenized text; cold-start (no memory) also catches all
three via the new context-free rules. Full regression: 4 docs unchanged
counts, zero new FPs (one scare was a checker-script bug, not the app).

## 2026-07-17 — Session 13: v0.5.0 field-verified — all green

Dillan re-ran everything on the rebuilt app. Round-trip line comes back
fully tokenized (paraphrased key caught). All three re-verified files:
xlsx zero leaks + formula intact, eml token-consistent, escalation docx
zero leaks with all negatives preserved. Every known issue from four
field-test rounds is closed. Current state: v0.5.0, Mac .app validated,
detection engine hardened through adversarial round-trip testing.
Remaining roadmap: review-before-commit, client profiles, MCP server
mode, category toggles, rebuilt PDFs/OCR, Windows build + Defender/DLP
coexistence test, code signing. Blog draft can be written on request —
the arc is complete: idea → PoC → app → field-hardened v0.5.0 in one day.

## 2026-07-17 — Session 14: proper installers (v0.5.1) → Windows next

Dillan's ask: stop living in the CLI. macOS: build_macos.sh now emits a
DMG (hdiutil, volume with /Applications symlink — standard drag-to-
install), plus "Build DocScrub.command" so rebuilds are a double-click
in Finder. Windows: full Inno Setup pipeline — docscrub.iss (stable
AppId for clean upgrades, Start Menu + optional desktop shortcut,
uninstaller, LZMA2) and build_windows.bat upgraded to auto-detect ISCC,
pass the version from the package, and fall back gracefully to the bare
exe if Inno Setup isn't installed. SmartScreen will warn on the unsigned
Setup.exe ("More info → Run anyway") — code signing cert remains the
production to-do. Neither installer path is testable in the Linux
sandbox (hdiutil/ISCC are OS-native) — first Windows build doubles as
validation + the long-awaited Defender/DLP coexistence experiment.

**Packaging decision (2026-07-17):** finished product ships fully
self-contained — PyInstaller/Nuitka frozen exe or signed MSIX for Intune
deployment, NER model bundled (small model ~12MB in base installer, large
~400MB as optional offline "accuracy pack"). No runtime downloads ever:
customer networks are proxied/allowlisted (exactly what broke model
downloads in the build sandbox), and a data-control tool that phones home
undermines its own trust story. Only network touch: optional *signed*
detection-rule-pack updates — checked for, never required; air-gapped
installs stay fully functional; distributable via RMM instead.
