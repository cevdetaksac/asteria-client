# Shared console command blacklist — identical copy lives in the agent repo.
# Deny-by-default on parse/normalize failure. Cover destructive OS / agent
# self-harm patterns. Keep in sync with asteria-client/console_blacklist.py.
from __future__ import annotations
import re
from typing import Optional, Tuple

MAX_COMMAND_CHARS = 4000
MAX_TIMEOUT_SEC = 120
DEFAULT_TIMEOUT_SEC = 30
MAX_OUTPUT_BYTES = 64 * 1024

# Patterns applied after normalize(). All are case-insensitive substring/regex.
_BLOCK_RES = [
    # Disk / partition wipe
    r"\bformat\b",
    r"\bdiskpart\b",
    r"\bclean\s+all\b",
    r"\brecover\b.*\bdisk\b",
    # Cipher wipe / secure erase
    r"\bcipher\s+/w",
    # Shadow / backup delete
    r"\bvssadmin\b.*\bdelete\b",
    r"\bwbadmin\b.*\bdelete\b",
    r"\bwmic\b.*\bshadowcopy\b.*\bdelete\b",
    # Boot config
    r"\bbcdedit\b",
    r"\bbootrec\b",
    # Shutdown / reboot (dedicated reboot command exists)
    r"\bshutdown\b",
    r"\brestart-computer\b",
    r"\bstop-computer\b",
    r"\binit\s+0\b",
    # User / account destruction
    r"\bnet\s+user\b.*/delete\b",
    r"\bnet\s+localgroup\b.*/delete\b",
    r"\bremove-localuser\b",
    r"\bremove-aduser\b",
    r"\bremove-localgroupmember\b",
    # Firewall kill-all
    r"\bnetsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off\b",
    r"\bset-netfirewallprofile\b.*\benabled\s+\$?false\b",
    # Agent / guardian self-harm
    r"asteria[-_]?client",
    r"honeypot[-_]?client",
    r"asteria[-_]?encode",
    r"asteria[-_]?guardian",
    r"cloud[-_]?honeypot",
    r"\\program\s*files\\asteria\\",
    r"\\programdata\\asteria\\",
    r"schtasks\b.*asteria",
    r"sc(\.exe)?\s+(delete|stop|config)\b.*asteria",
    r"stop-service\b.*asteria",
    r"remove-service\b.*asteria",
    r"uninstall-package\b.*asteria",
    # Registry hive delete / load wipe
    r"\breg\s+(delete|unload|restore)\b",
    r"\bremove-itemproperty\b.*hk(lm|cu|u|cr|cc)",
    r"\bremove-item\b.*hk(lm|cu|u|cr|cc):",
    # Execution policy system-wide unrestricted
    r"\bset-executionpolicy\b.*\bunrestricted\b",
    # Ownership / ACL of Windows
    r"\btakeown\b.*\\windows(?:\\|\s|$)",
    r"\bicacls\b.*\\windows(?:\\|\s|$)",
    # Service delete
    r"\bsc(\.exe)?\s+delete\b",
    r"\bremove-service\b",
    # Encoding / download-exec obfuscation
    r"-encodedcommand\b",
    r"-enc\b\s+[a-z0-9+/=]{20,}",
    r"\biex\b",
    r"\binvoke-expression\b",
    r"\binvoke-webrequest\b.*\|\s*iex\b",
    r"\bdownloadstring\b",
    r"\bdownloadfile\b",
    r"\bfrombase64string\b",
    r"\b[system\.convert]::",
    # Recursive wipe of system roots
    r"\brd\s+/s\b",
    r"\brmdir\s+/s\b",
    r"\bremove-item\b.*-recurse\b.*[c-z]:\\",
    r"\bdel\s+/[a-z]*s\b.*\\windows\\",
    r"\bdel\s+/[a-z]*s\b.*\\users\\",
    r"\bdel\s+/[a-z]*s\b.*\\program",
    # Disk wipe via powershell
    r"\bclear-disk\b",
    r"\binitialize-disk\b",
    r"\bremove-partition\b",
    r"\bformat-volume\b",
]

_COMPILED = [re.compile(p, re.I) for p in _BLOCK_RES]


def normalize_command(raw: str) -> Optional[str]:
    """Normalize for matching. None = unparseable → deny."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return None
    s = raw.replace("\x00", " ")
    # Collapse powershell backticks / caret escapes used for obfuscation
    s = s.replace("`", "").replace("^", "")
    # Decode common &xx; and %XX? leave as-is if fails; strip NUL already done
    s = re.sub(r"[\t\r\n]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return None
    if len(s) > MAX_COMMAND_CHARS:
        return None
    # Reject if mostly non-printable (obfuscation)
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "çğıöşüÇĞİÖŞÜ")
    if printable / max(len(s), 1) < 0.85:
        return None
    return s


def is_blocked(command: str, shell: str = "cmd") -> Tuple[bool, str]:
    """Return (blocked, reason). blocked=True means must never run."""
    norm = normalize_command(command)
    if norm is None:
        return True, "unparseable_or_empty"
    # Shell-specific: powershell -EncodedCommand already covered
    for rx in _COMPILED:
        if rx.search(norm):
            return True, f"blacklist:{rx.pattern[:60]}"
    # Path-sensitive deletes of system dirs even without /s flag combo
    low = norm.lower()
    sys_roots = (
        r"c:\windows", r"c:\program files", r"c:\programdata\asteria",
        r"%systemroot%", r"%windir%", r"%programfiles%",
    )
    if re.search(r"\b(del|erase|rd|rmdir|remove-item)\b", low):
        for root in sys_roots:
            if root in low:
                return True, f"blacklist:system_path:{root}"
    return False, ""


def validate_shell(shell: str) -> Optional[str]:
    s = (shell or "").strip().lower()
    if s in ("cmd", "cmd.exe"):
        return "cmd"
    if s in ("powershell", "pwsh", "powershell.exe", "pwsh.exe"):
        return "powershell"
    return None


def clamp_timeout(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SEC
    return max(5, min(MAX_TIMEOUT_SEC, n))
