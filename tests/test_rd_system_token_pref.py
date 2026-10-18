# -*- coding: utf-8 -*-
"""4.9.138: SYSTEM+TokenSessionId preferred; Default lock curtain stays put."""
from client_rd_winlogon import console_start_secure_desktop


def test_lock_curtain_default_desk_stays_default_even_if_logonui():
    assert console_start_secure_desktop(
        username="caksac",
        logonui_present=True,
        session_locked=True,
        input_desktop="Default",
    ) is False


def test_winlogon_desk_still_secure():
    assert console_start_secure_desktop(
        username="",
        logonui_present=True,
        session_locked=True,
        input_desktop="Winlogon",
    ) is True


def test_open_session_token_doc_prefers_system_over_logonui():
    import client_rd_winlogon as m
    src = m.open_session_interactive_token.__doc__ or ""
    assert "SYSTEM" in src and "LogonUI" in src
