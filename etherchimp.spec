# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Etherchimp standalone binary

import sys
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# Collect all data and imports for key packages
datas = []
binaries = []
hiddenimports = []

# Collect Flask and related packages
tmp_ret = collect_all('flask')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all('flask_socketio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all('socketio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all('engineio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

# Collect Scapy (critical for packet capture)
tmp_ret = collect_all('scapy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

# Collect plotting libraries
tmp_ret = collect_all('matplotlib')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all('pandas')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all('numpy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

# Add application-specific data files
datas += [
    ('templates', 'templates'),
    ('static', 'static'),
    ('backend', 'backend'),
]

# Additional hidden imports for runtime modules
hiddenimports += [
    'flask.json.provider',
    'flask.json.tag',
    'engineio.async_drivers.threading',
    'engineio.async_drivers.gevent',
    'socketio.packet',
    'scapy.all',
    'scapy.layers.all',
    'scapy.utils',
    'backend.routes.api',
    'backend.processing.pcap_processor',
    'backend.processing.live_capture',
    'backend.processing.remote_capture',
    'backend.processing.threat_detection',
    'backend.utils.log_cleanup',
    'backend.utils.helpers',
    'backend.utils.ip_filters',
]

# Analysis
a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Remove duplicate data files
a.datas = list({tuple(d) for d in a.datas})

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# For single file executable (slower startup, more portable)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='etherchimp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Uncomment below for directory-based distribution (faster startup)
# exe = EXE(
#     pyz,
#     a.scripts,
#     [],
#     exclude_binaries=True,
#     name='etherchimp',
#     debug=False,
#     bootloader_ignore_signals=False,
#     strip=False,
#     upx=True,
#     console=True,
#     disable_windowed_traceback=False,
#     argv_emulation=False,
#     target_arch=None,
#     codesign_identity=None,
#     entitlements_file=None,
# )
#
# coll = COLLECT(
#     exe,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     name='etherchimp',
# )
