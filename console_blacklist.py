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
    # format COMMAND only (not Format-Table/Format-List/Format-Volume handled below)
    r"(?:^|[;&|(]|\bcmd(?:\.exe)?\s+/[ck])\s*format(?:\.com|\.exe)?\b(?!-)",
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
    r"\[system\.convert\]::",
    r"\[convert\]::",
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


_ENV_MAP = {
    "systemroot": r"c:\windows", "windir": r"c:\windows", "systemdrive": "c:",
    "programfiles": r"c:\program files", "programfiles(x86)": r"c:\program files (x86)",
    "programw6432": r"c:\program files", "programdata": r"c:\programdata",
    "allusersprofile": r"c:\programdata", "public": r"c:\users\public",
    "homedrive": "c:", "commonprogramfiles": r"c:\program files\common files",
}

_DELETE_VERB = re.compile(r"(?:^|[\s;&|(])(remove-item|ri|rm|rmdir|rd|del|erase|clear-recyclebin)(?=$|[\s;&|)])")
_FORCE_FLAG = re.compile(r"(?:^|\s)(?:-r|-rec\w*|-fo\w*|/s|/q|/f|/a)(?=$|[\s:])")
_PROTECTED = [
    re.compile(r"(?:^|[\s=,(])(?:\\\\\?\\)?[a-z]:\\?(?:\*(?:\.\*)?)?(?=$|[\s;|&),])"),  # drive root: c:  c:\  c:\*  c:\*.*
    re.compile(r"(?:^|[\s=,(])\\\*?(?=$|[\s;|&),])"),                               # bare "\" root
    re.compile(r"[a-z]:\\(?:windows|winnt|boot|recovery|system volume information)(?=$|[\\\s;|&),*])"),
    re.compile(r"[a-z]:\\program files(?: \(x86\))?(?=$|[\\\s;|&),*])"),
    re.compile(r"[a-z]:\\programdata(?=$|[\s;|&),*]|\\\*|\\asteria)"),
    re.compile(r"[a-z]:\\users(?=$|[\s;|&),*]|\\\*)"),
]


def _match_form(norm: str) -> str:
    """Canonical lowercase form for rule matching only (never executed).

    Strips quotes/carets/backticks, expands well-known env vars (cmd %x%,
    PowerShell $env:x / ${env:x}), unifies path separators.
    """
    s = norm.lower()
    s = s.replace('"', "").replace("'", "").replace("^", "").replace("`", "")
    def _env(m):
        k = (m.group(1) or m.group(2) or m.group(3) or "").lower()
        return _ENV_MAP.get(k, m.group(0))
    s = re.sub(r"%([a-z0-9_()]+)%|\$\{env:([a-z0-9_()]+)\}|\$env:([a-z0-9_()]+)", _env, s)
    s = re.sub(r"([a-z]):/", r"\1:\\", s)
    s = re.sub(r"[a-z]:\\[^\s;|&]*", lambda m: m.group(0).replace("/", "\\"), s)
    s = re.sub(r"\\{2,}(?!\?)", r"\\", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def is_blocked(command: str, shell: str = "cmd") -> Tuple[bool, str]:
    """Return (blocked, reason). blocked=True means must never run."""
    norm = normalize_command(command)
    if norm is None:
        return True, "unparseable_or_empty"
    low = _match_form(norm)
    for rx in _COMPILED:
        if rx.search(norm) or rx.search(low):
            return True, f"blacklist:{rx.pattern[:60]}"
    if _DELETE_VERB.search(low):
        if re.search(r"%[a-z0-9_()]+%|\$\{?env:", low):
            return True, "blacklist:delete_with_unresolved_env"
        for rx in _PROTECTED:
            if rx.search(low):
                return True, "blacklist:delete_protected_path"
        if _FORCE_FLAG.search(low) and re.search(r"(?:^|\s)\*(?:\.\*)?(?=$|\s)", low):
            return True, "blacklist:forced_wildcard_delete"
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
