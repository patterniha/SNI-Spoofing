# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['E:\\thief\\Desktop\\SNI-Spoofing-1.0\\gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['main'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SMART-FOX',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['E:\\thief\\Desktop\\SNI-Spoofing-1.0\\icon\\_generated\\4aa2ff22-55a1-49bf-a3de-5f9b7f7c9861.ico'],
)
