"""Set Windows GpuPreference for asteria-encode.exe (Optimus: try HighPerf=2 for NVENC)."""
from pathlib import Path
import winreg

def set_pref(exe: Path, preference: int = 2) -> None:
    # 0=auto 1=power saving 2=high performance
    key = winreg.CreateKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\DirectX\UserGpuPreferences",
    )
    winreg.SetValueEx(key, str(exe.resolve()), 0, winreg.REG_SZ, f"GpuPreference={preference};")
    winreg.CloseKey(key)
    print(f"GpuPreference={preference} for {exe}")

if __name__ == "__main__":
    import sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        r"C:\asteria-client-workspace\asteria-client\sidecar\asteria-encode\target\x86_64-pc-windows-gnullvm\release\asteria-encode.exe"
    )
    pref = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    set_pref(p, pref)
