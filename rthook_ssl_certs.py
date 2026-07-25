# PyInstaller runtime hook — fix TLS CA path before any HTTPS call.
# onefile extracts to %TEMP%\_MEI* which can vanish (RDP session temp cleanup).
import os
import sys
import shutil

def _bootstrap_ca():
    try:
        mei = getattr(sys, "_MEIPASS", "") or ""
        stable_dir = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
        stable = os.path.join(stable_dir, "cacert.pem")
        candidates = []
        if mei:
            candidates.append(os.path.join(mei, "certifi", "cacert.pem"))
            candidates.append(os.path.join(mei, "cacert.pem"))
        if os.path.isfile(stable):
            candidates.insert(0, stable)
        try:
            import certifi
            candidates.append(certifi.where())
        except Exception:
            pass
        src = next(
            (p for p in candidates if p and os.path.isfile(p) and os.path.getsize(p) > 1000),
            None,
        )
        if not src:
            return
        try:
            os.makedirs(stable_dir, exist_ok=True)
            if os.path.abspath(src) != os.path.abspath(stable):
                shutil.copy2(src, stable)
            if os.path.isfile(stable):
                src = stable
        except Exception:
            pass
        os.environ["SSL_CERT_FILE"] = src
        os.environ["REQUESTS_CA_BUNDLE"] = src
    except Exception:
        pass

_bootstrap_ca()
