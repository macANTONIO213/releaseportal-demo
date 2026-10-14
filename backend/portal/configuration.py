"""Windows user-bound DPAPI protection for local integration configuration.
Shared hosting should use its approved secret mount/vault instead.
"""
import ctypes
import json
import os
from pathlib import Path

def runtime_path():
    return Path(os.environ.get('PORTAL_RUNTIME_DIR', str(Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'state'))) / 'ReleasePortal' / 'runtime')))

def crypt(data, decrypt=False):
    if os.name != 'nt':
        raise RuntimeError('The local configuration helper requires Windows DPAPI; use a vault on shared hosting.')
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    api = ctypes.WinDLL('crypt32', use_last_error=True)
    function = api.CryptUnprotectData if decrypt else api.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise RuntimeError('User-bound configuration encryption failed.')
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel = ctypes.WinDLL('kernel32')
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(result.data)

def read_config(path):
    data = path.read_bytes()
    if data.startswith(b'DPAPI\n'):
        data = crypt(data[6:], decrypt=True)
    return json.loads(data)

def write_local_config(path, value):
    path.write_bytes(b'DPAPI\n' + crypt(json.dumps(value).encode()))
