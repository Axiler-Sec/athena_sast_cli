# -*- mode: python ; coding: utf-8 -*-
# One-file athena binary. Auth is env-only at runtime — do not collect .env.
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("pkg")

a = Analysis(
    ["../athena.py"],
    pathex=[".."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[".env", "pytest", "tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="athena",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
)
