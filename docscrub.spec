# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for DocScrub. Build on the TARGET OS:
    macOS   : ./build_macos.sh
    Windows : build_windows.bat
    Linux   : pyinstaller docscrub.spec --noconfirm
Produces dist/DocScrub/ (one-dir bundle: reliable with spaCy/Presidio).
"""

import importlib.util
import sys

from PyInstaller.utils.hooks import collect_all, copy_metadata

datas, binaries, hiddenimports = [], [], []

for pkg in ("spacy", "thinc", "presidio_analyzer", "presidio_anonymizer",
            "phonenumbers", "docx", "pypdf", "tldextract", "openpyxl",
            "olefile"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

# Native window (optional — falls back to browser UI when absent)
if importlib.util.find_spec("webview") is not None:
    d, b, h = collect_all("webview")
    datas += d; binaries += b; hiddenimports += h

# Bundle whichever spaCy English model is installed at build time (optional —
# the app falls back to a pattern-only blank pipeline if none is bundled).
for model in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
    if importlib.util.find_spec(model) is not None:
        d, b, h = collect_all(model)
        datas += d; binaries += b; hiddenimports += h
        datas += copy_metadata(model)
        break

# App static assets (web UI)
datas += [("docscrub/static", "docscrub/static")]

hiddenimports += ["docx", "pypdf", "flask"]

a = Analysis(
    ["launcher.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "IPython", "jupyter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

_ICON = ("assets/docscrub.ico" if sys.platform == "win32"
         else "assets/docscrub.icns" if sys.platform == "darwin" else None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DocScrub",
    # Windows needs a console for CLI output; on macOS/Linux the flag is
    # irrelevant for terminal use and False gives clean .app behavior.
    console=(sys.platform == "win32"),
    icon=_ICON,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="DocScrub",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="DocScrub.app",
        icon="assets/docscrub.icns",
        bundle_identifier="dev.valorops.docscrub",
        info_plist={
            "CFBundleName": "DocScrub",
            "CFBundleDisplayName": "DocScrub",
            "CFBundleShortVersionString": "0.5.1",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
