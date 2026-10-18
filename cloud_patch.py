# -*- coding: utf-8 -*-
"""Phase-1 cloud patch. Run from repo root. Idempotent-ish; fails loudly on anchor miss."""
import re, pathlib, sys
R = pathlib.Path('.')
def rd(p): return (R/p).read_text(encoding='utf-8')
def wr(p, s): (R/p).parent.mkdir(parents=True, exist_ok=True); (R/p).write_text(s, encoding='utf-8')
def sub1(p, old, new, count=1):
    s = rd(p)
    if old not in s:
        if new in s: print('skip(already)', p); return
        sys.exit(f'ANCHOR MISS in {p}: {old[:80]!r}')
    wr(p, s.replace(old, new, count)); print('patched', p)

# 1) checkout UnboundLocalError
sub1('routes_billing.py', '    quote = quote_total(interval_n, extra_n)\n', '    price_quote = quote_total(interval_n, extra_n)\n')
sub1('routes_billing.py', '        "quote": quote,\n', '        "quote": price_quote,\n')

# 2) /healthz cheap
sub1('routes_api.py', '''@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    try:
        total_clients = db.query(Client).count()
        return {"status": "ok", "clients": total_clients}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})
''', '''@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    """Cheap liveness + DB ping (no table scans). 200 ok / 503 db down."""
    import time as _t
    from sqlalchemy import text as _text
    t0 = _t.monotonic()
    try:
        db.execute(_text("SELECT 1"))
        return {"status": "ok", "db": "ok", "db_ms": round((_t.monotonic() - t0) * 1000, 1)}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "db": "down", "detail": type(e).__name__})
''')

# 3) single source client versions
wr('client_versions.py', '''"""Single source for production floor / recommended agent version.

recommended = newest GitHub release (from github_release cache; refreshed in background,
never blocks a request) else ASTERIA_RECOMMENDED_CLIENT env else fallback constant.
floor = ASTERIA_PRODUCTION_FLOOR env else fallback constant (contract FLEET.md).
"""
from __future__ import annotations

import os
import re
import threading
import time

PRODUCTION_FLOOR_FALLBACK = "4.9.121"
RECOMMENDED_FALLBACK = "4.9.121"
_VER = re.compile(r"^\\d+\\.\\d+\\.\\d+$")
_refresh_lock = threading.Lock()
_last_kick = 0.0


def _norm(v) -> str:
    v = str(v or "").strip().lstrip("vV")
    return v if _VER.match(v) else ""


def _kick_refresh() -> None:
    global _last_kick
    now = time.time()
    if now - _last_kick < 60 or not _refresh_lock.acquire(blocking=False):
        return
    _last_kick = now

    def run():
        try:
            from github_release import fetch_latest_release
            fetch_latest_release()
        except Exception:
            pass
        finally:
            _refresh_lock.release()

    threading.Thread(target=run, name="client-version-refresh", daemon=True).start()


def production_floor() -> str:
    return _norm(os.getenv("ASTERIA_PRODUCTION_FLOOR")) or PRODUCTION_FLOOR_FALLBACK


def recommended_client() -> str:
    try:
        import github_release as gr
        data = gr._cache.get("data") or {}
        fresh = (time.time() - float(gr._cache.get("at") or 0)) < gr.CACHE_TTL_SEC
        if not fresh:
            _kick_refresh()
        v = _norm(data.get("tag") or data.get("version"))
        if v:
            return v
    except Exception:
        pass
    return _norm(os.getenv("ASTERIA_RECOMMENDED_CLIENT")) or RECOMMENDED_FALLBACK
''')
sub1('security_resilience.py', '''        "production_floor": "4.9.121",
        "recommended_client": "4.9.121",''', '''        "production_floor": _cv.production_floor(),
        "recommended_client": _cv.recommended_client(),''')
s = rd('security_resilience.py')
if 'import client_versions as _cv' not in s:
    # insert after the first block of imports
    lines = s.split('\n'); idx = 0
    for i, l in enumerate(lines):
        if l.startswith('import ') or l.startswith('from '): idx = i
        elif idx and l.strip() and not l.startswith((' ', ')')) and i > idx + 1: break
    lines.insert(idx + 1, 'import client_versions as _cv')
    wr('security_resilience.py', '\n'.join(lines)); print('patched import security_resilience.py')

# Jinja globals in every Jinja2Templates instance
for p in sorted(R.glob('*.py')):
    s = rd(p.name)
    if p.name == 'template_env.py':
        if 'recommended_client' not in s:
            s = s.replace('    templates.env.globals["asset_v"] = asset_v\n',
                '    templates.env.globals["asset_v"] = asset_v\n'
                '    import client_versions as _cv\n'
                '    templates.env.globals["production_floor"] = _cv.production_floor\n'
                '    templates.env.globals["recommended_client"] = _cv.recommended_client\n')
            wr(p.name, s); print('patched globals', p.name)
        continue
    m = re.search(r'^(\w+) = Jinja2Templates\([^\n]*\)\n', s, re.M)
    if m and 'recommended_client' not in s:
        v = m.group(1)
        add = (f'import client_versions as _cv_glob\n'
               f'{v}.env.globals["production_floor"] = _cv_glob.production_floor\n'
               f'{v}.env.globals["recommended_client"] = _cv_glob.recommended_client\n')
        s = s[:m.end()] + add + s[m.end():]
        wr(p.name, s); print('patched globals', p.name)

sub1('templates/base.html', '  <script src="/static/js/app.js?', '''  <script>window.PRODUCTION_FLOOR = {{ production_floor()|tojson }}; window.RECOMMENDED_CLIENT = {{ recommended_client()|tojson }};</script>
  <script src="/static/js/app.js?''')
sub1('static/js/pages/overview.js', """  var PRODUCTION_FLOOR = '4.9.121';
  var RECOMMENDED_CLIENT = '4.9.121';""", """  // Single source: server injects window.PRODUCTION_FLOOR / RECOMMENDED_CLIENT (client_versions.py)
  var PRODUCTION_FLOOR = window.PRODUCTION_FLOOR || '4.9.121';
  var RECOMMENDED_CLIENT = window.RECOMMENDED_CLIENT || PRODUCTION_FLOOR;""")
sub1('templates/dashboard.html', 'floor/önerilen ≥4.9.121 (NLA RDP)', 'floor ≥{{ production_floor() }} · önerilen ≥{{ recommended_client() }}')

# 4) Incident response
sub1('helpers.py', "    'disable_all_users',\n    'reset_password', 'kill_process',", "    'disable_all_users', 'contain_user',\n    'reset_password', 'kill_process',")
sub1('helpers.py', "    'reset_password', 'disable_account', 'disable_all_users', 'enable_lockdown',\n", "    'reset_password', 'disable_account', 'disable_all_users', 'enable_lockdown',\n    # IR containment: logoff + password reset (+disable) in one shot (contract 1.4.91)\n    'contain_user',\n")
sub1('routes_v4.py', '''    if req.command_type == 'reset_password':
        target_user = (req.params.get('username') or '').strip()''', '''    # Typed confirmation (contract 1.4.91): when the dashboard sends confirm_name it
    # must match this server's name; the field is stripped before queueing.
    if isinstance(req.params, dict) and 'confirm_name' in req.params:
        typed = str(req.params.pop('confirm_name') or '').strip().lower()
        names = set()
        try:
            from helpers import get_client_computer_name
            names.add(str(get_client_computer_name(client) or '').strip().lower())
        except Exception:
            pass
        sn = str(getattr(client, 'server_name', '') or '').strip()
        names.add(sn.lower())
        if sn.endswith(')') and ' (' in sn:
            names.add(sn.rsplit(' (', 1)[0].strip().lower())
        names.discard('')
        if not typed or typed not in names:
            raise HTTPException(status_code=400, detail="confirm_name does not match server name")
    if req.command_type == 'contain_user':
        target_user = (req.params.get('username') or '').strip()
        new_pwd = (req.params.get('new_password') or '')
        if not target_user:
            raise HTTPException(status_code=400, detail="username gerekli")
        if not new_pwd or len(str(new_pwd)) < 8:
            raise HTTPException(status_code=400, detail="new_password en az 8 karakter olmalı")
        if 'disable' in req.params:
            req.params['disable'] = bool(req.params.get('disable'))
    if req.command_type in ('enable_lockdown',):
        import ipaddress as _ip
        mip = str(req.params.get('management_ip') or '').strip()
        try:
            _ip.ip_address(mip)
        except ValueError:
            raise HTTPException(status_code=400, detail="management_ip gerekli (geçerli IP)")
    if req.command_type == 'reset_password':
        target_user = (req.params.get('username') or '').strip()''')
sub1('static/js/app.js', "  reset_password: { titleKey: 'reset_pwd_btn',", "  contain_user: { titleKey: 'ir_contain_btn', bodyKey: 'ir_contain_body', btnKey: 'ir_contain_btn', cls: 'btn-danger' },\n  reset_password: { titleKey: 'reset_pwd_btn',")

wr('static/js/incident_response.js', r'''/* Incident response (contract 1.4.91): typed-name confirmation for high-risk IR.
 * Uses existing client commands: contain_user, disable_all_users, enable_lockdown.
 * All strings via i18n keys (ir_*). */
(function () {
  'use strict';
  var H = window.H = window.H || {};
  function t(k, fb) { try { var v = H.t && H.t(k); return (v && v !== k) ? v : (fb || k); } catch (e) { return fb || k; } }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
  function serverName() { return String(window.ASTERIA_SERVER_NAME || '').trim(); }
  function genPassword() {
    var cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%*-_';
    var a = new Uint32Array(20); (window.crypto || window.msCrypto).getRandomValues(a);
    var out = ''; for (var i = 0; i < a.length; i++) out += cs[a[i] % cs.length];
    return out;
  }
  function ensureModal() {
    var m = document.getElementById('irModal');
    if (m) return m;
    var d = document.createElement('div');
    d.innerHTML =
      '<div class="modal modal-blur fade" id="irModal" tabindex="-1"><div class="modal-dialog modal-dialog-centered"><div class="modal-content">' +
      '<div class="modal-status bg-danger"></div>' +
      '<div class="modal-header"><h5 class="modal-title" id="irTitle"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>' +
      '<div class="modal-body"><p id="irBody" class="text-secondary"></p><div id="irExtra"></div>' +
      '<label class="form-label mt-3" id="irTypeLabel"></label>' +
      '<input type="text" class="form-control" id="irTypeInput" autocomplete="off" spellcheck="false"></div>' +
      '<div class="modal-footer"><button type="button" class="btn btn-link link-secondary" data-bs-dismiss="modal" id="irCancel"></button>' +
      '<button type="button" class="btn btn-danger" id="irOk" disabled></button></div>' +
      '</div></div></div>';
    document.body.appendChild(d.firstChild);
    m = document.getElementById('irModal');
    document.getElementById('irTypeInput').addEventListener('input', function () {
      var ok = this.value.trim().toLowerCase() === serverName().toLowerCase() && serverName() !== '';
      document.getElementById('irOk').disabled = !ok;
    });
    return m;
  }
  /** kind: 'contain' | 'disable_all' | 'lockdown' */
  H.irOpen = function (kind, username) {
    var m = ensureModal(), extra = document.getElementById('irExtra');
    var name = serverName();
    document.getElementById('irCancel').textContent = t('cancel_btn', 'Cancel');
    document.getElementById('irTypeLabel').innerHTML = esc(t('ir_type_name', 'Type the server name to confirm:')) + ' <code>' + esc(name || '?') + '</code>';
    var inp = document.getElementById('irTypeInput'); inp.value = '';
    var okBtn = document.getElementById('irOk'); okBtn.disabled = true;
    extra.innerHTML = '';
    var title, body, okText, build;
    if (kind === 'contain') {
      var pwd = genPassword();
      title = t('ir_contain_btn', 'Contain user') + ': ' + username;
      body = t('ir_contain_body', 'Logs off all sessions of this user, sets a new password and disables the account.');
      extra.innerHTML = '<label class="form-label">' + esc(t('ir_new_password', 'New password (save it now)')) + '</label>' +
        '<div class="input-group"><input type="text" class="form-control font-monospace" id="irPwd" value="' + esc(pwd) + '">' +
        '<button class="btn" type="button" id="irPwdCopy"><i class="ti ti-copy"></i></button></div>' +
        '<label class="form-check mt-2"><input class="form-check-input" type="checkbox" id="irDisable" checked><span class="form-check-label">' + esc(t('ir_also_disable', 'Also disable the account')) + '</span></label>';
      document.getElementById('irPwdCopy').onclick = function () { try { navigator.clipboard.writeText(document.getElementById('irPwd').value); } catch (e) {} };
      okText = t('ir_contain_btn', 'Contain user');
      build = function () {
        var p = document.getElementById('irPwd').value;
        if (!p || p.length < 8) { H.showToast && H.showToast(t('ir_pwd_short', 'Password must be at least 8 characters'), 'danger'); return null; }
        return ['contain_user', { username: username, new_password: p, disable: document.getElementById('irDisable').checked }];
      };
    } else if (kind === 'disable_all') {
      title = t('disable_all_users_btn', 'Disable All Users');
      body = t('confirm_disable_all_body', 'All local accounts will be disabled and logged off.');
      extra.innerHTML = '<label class="form-label">' + esc(t('ir_exclude_label', 'Keep these accounts enabled (comma separated)')) + '</label>' +
        '<input type="text" class="form-control" id="irExclude" placeholder="Administrator2">';
      okText = t('disable_all_users_short', 'Disable all');
      build = function () {
        var ex = (document.getElementById('irExclude').value || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean);
        return ['disable_all_users', { logoff: true, exclude: ex }];
      };
    } else {
      title = t('ir_lockdown_btn', 'Emergency lockdown');
      body = t('ir_lockdown_body', 'Blocks all inbound access except the management IP for the selected duration.');
      extra.innerHTML = '<div class="row g-2"><div class="col-8"><label class="form-label">' + esc(t('ir_mgmt_ip', 'Management IP (stays allowed)')) + '</label>' +
        '<input type="text" class="form-control" id="irMgmtIp" value="' + esc(window.ASTERIA_OPERATOR_IP || '') + '"></div>' +
        '<div class="col-4"><label class="form-label">' + esc(t('ir_duration_min', 'Minutes')) + '</label>' +
        '<input type="number" class="form-control" id="irDur" value="60" min="5" max="1440"></div></div>';
      okText = t('ir_lockdown_btn', 'Emergency lockdown');
      build = function () {
        var ip = (document.getElementById('irMgmtIp').value || '').trim();
        if (!ip) { H.showToast && H.showToast(t('ir_mgmt_ip_required', 'Management IP is required'), 'danger'); return null; }
        var dur = parseInt(document.getElementById('irDur').value, 10) || 60;
        return ['enable_lockdown', { management_ip: ip, duration_minutes: Math.max(5, Math.min(1440, dur)) }];
      };
    }
    document.getElementById('irTitle').innerHTML = '<i class="ti ti-alert-octagon me-2 text-danger"></i>' + esc(title);
    document.getElementById('irBody').textContent = body;
    okBtn.textContent = okText;
    okBtn.onclick = function () {
      var r = build(); if (!r) return;
      r[1].confirm_name = inp.value.trim();
      var inst = bootstrap.Modal.getInstance(m); if (inst) inst.hide();
      H.sendCommand(r[0], r[1], { skipConfirm: true });
    };
    new bootstrap.Modal(m).show();
    setTimeout(function () { inp.focus(); }, 300);
  };
})();
''')

# users page: row action + header buttons + IR card
sj = rd('static/js/server_mgmt.js')
old_row = """            '<button type="button" class="btn btn-sm btn-outline-orange" title="Oturumu kapat" onclick="H.sendCommand(\\'logoff_user\\',{username:\\'' + qName + '\\'})"><i class="ti ti-logout"></i></button>' +"""
if old_row not in sj and 'irOpen' not in sj: sys.exit('ANCHOR MISS server_mgmt row')
if 'irOpen' not in sj:
    sj = sj.replace(old_row, old_row + """
            '<button type="button" class="btn btn-sm btn-outline-danger" title="' + esc(t('ir_contain_btn', 'Contain user')) + '" onclick="H.irOpen(\\'contain\\', \\'' + qName + '\\')"><i class="ti ti-shield-lock"></i></button>' +""")
    wr('static/js/server_mgmt.js', sj); print('patched server_mgmt.js')

u = rd('templates/dashboard_server_users.html')
if 'irOpen' not in u:
    old_btn = """onclick="H.sendCommand('disable_all_users',{logoff:true})\""""
    if old_btn not in u: sys.exit('ANCHOR MISS users disable_all')
    u = u.replace(old_btn, """onclick="H.irOpen('disable_all')\"""")
    hdr = """        <button type="button" class="btn btn-outline-primary" onclick="H.smRefreshUsers()">"""
    if hdr not in u: sys.exit('ANCHOR MISS users header')
    u = u.replace(hdr, """        <button type="button" class="btn btn-danger" onclick="H.irOpen('lockdown')">
          <i class="ti ti-alert-octagon me-1"></i><span data-i18n="ir_lockdown_btn">Emergency lockdown</span>
        </button>
""" + hdr, 1)
    # IR card: insert before the first card that holds the users table
    anchor = '<div class="card-header">'
    i = u.find(anchor)
    j = u.rfind('<div class="card', 0, i)
    card = """<div class="card border-danger mb-3" id="irCard">
      <div class="card-body d-flex flex-wrap align-items-center gap-2">
        <div class="me-auto">
          <h3 class="card-title text-danger mb-1"><i class="ti ti-urgent me-1"></i><span data-i18n="ir_card_title">Incident response</span></h3>
          <div class="text-secondary small" data-i18n="ir_card_sub">Use when this server is compromised. Every action needs the server name typed to confirm and is audit-logged.</div>
        </div>
        <button type="button" class="btn btn-outline-danger" onclick="H.irOpen('disable_all')"><i class="ti ti-users-minus me-1"></i><span data-i18n="disable_all_users_btn">Disable All Users</span></button>
        <button type="button" class="btn btn-danger" onclick="H.irOpen('lockdown')"><i class="ti ti-alert-octagon me-1"></i><span data-i18n="ir_lockdown_btn">Emergency lockdown</span></button>
      </div>
    </div>
    """
    u = u[:j] + card + u[j:]
    u = u.replace('<script src="/static/js/server_mgmt.js', """<script>window.ASTERIA_SERVER_NAME = {{ (client.server_name or '')|tojson }};{% if request and request.client %} window.ASTERIA_OPERATOR_IP = {{ (request.headers.get('cf-connecting-ip') or request.headers.get('x-real-ip') or request.client.host or '')|tojson }};{% endif %}</script>
<script src="/static/js/incident_response.js?v=20261018-ir1"></script>
<script src="/static/js/server_mgmt.js""", 1)
    wr('templates/dashboard_server_users.html', u); print('patched users template')

# i18n (TR via \u escapes to stay ASCII-safe through any pipe)
EN = {
 'ir_card_title': 'Incident response',
 'ir_card_sub': 'Use when this server is compromised. Every action needs the server name typed to confirm and is audit-logged.',
 'ir_contain_btn': 'Contain user',
 'ir_contain_body': 'Logs off all sessions of this user, sets a new password and (optionally) disables the account.',
 'ir_new_password': 'New password (save it now)',
 'ir_also_disable': 'Also disable the account',
 'ir_pwd_short': 'Password must be at least 8 characters',
 'ir_exclude_label': 'Keep these accounts enabled (comma separated)',
 'ir_lockdown_btn': 'Emergency lockdown',
 'ir_lockdown_body': 'Blocks all inbound access to the server except the management IP for the selected duration.',
 'ir_mgmt_ip': 'Management IP (stays allowed)',
 'ir_mgmt_ip_required': 'Management IP is required',
 'ir_duration_min': 'Minutes',
 'ir_type_name': 'Type the server name to confirm:',
}
TR = {
 'ir_card_title': 'Olay m\\u00fcdahalesi',
 'ir_card_sub': 'Sunucu ele ge\\u00e7irildi\\u011finde kullan\\u0131n. Her i\\u015flem sunucu ad\\u0131n\\u0131n yaz\\u0131lmas\\u0131yla onaylan\\u0131r ve denetim kayd\\u0131na yaz\\u0131l\\u0131r.',
 'ir_contain_btn': 'Kullan\\u0131c\\u0131y\\u0131 izole et',
 'ir_contain_body': 'Bu kullan\\u0131c\\u0131n\\u0131n t\\u00fcm oturumlar\\u0131n\\u0131 kapat\\u0131r, yeni \\u015fifre atar ve (iste\\u011fe ba\\u011fl\\u0131) hesab\\u0131 pasifle\\u015ftirir.',
 'ir_new_password': 'Yeni \\u015fifre (\\u015fimdi kaydedin)',
 'ir_also_disable': 'Hesab\\u0131 da pasifle\\u015ftir',
 'ir_pwd_short': '\\u015eifre en az 8 karakter olmal\\u0131',
 'ir_exclude_label': 'Aktif kalacak hesaplar (virg\\u00fclle ay\\u0131r\\u0131n)',
 'ir_lockdown_btn': 'Acil kilitleme',
 'ir_lockdown_body': 'Se\\u00e7ilen s\\u00fcre boyunca y\\u00f6netim IP\\u2019si d\\u0131\\u015f\\u0131ndaki t\\u00fcm gelen eri\\u015fimi engeller.',
 'ir_mgmt_ip': 'Y\\u00f6netim IP\\u2019si (izinli kal\\u0131r)',
 'ir_mgmt_ip_required': 'Y\\u00f6netim IP\\u2019si gerekli',
 'ir_duration_min': 'Dakika',
 'ir_type_name': 'Onaylamak i\\u00e7in sunucu ad\\u0131n\\u0131 yaz\\u0131n:',
}
for path, d in (('static/js/i18n/en.js', EN), ('static/js/i18n/tr.js', TR)):
    s = rd(path)
    if 'ir_card_title' in s: continue
    k = s.rfind('};')
    block = ''.join(f"    {key}: '{val}',\n" for key, val in d.items())
    pre = s[:k].rstrip()
    if not pre.endswith(','): pre += ','
    s = pre + '\n    // Incident response (1.4.91)\n' + block + s[k:]
    wr(path, s); print('patched', path)

# 5) Test infra
s = rd('database.py')
if 'ASTERIA_SKIP_DOTENV' not in s:
    s = s.replace("env_path = Path(__file__).parent / '.env'\ntry:\n    load_dotenv",
                  "env_path = Path(__file__).parent / '.env'\n# Tests/CI: never read the production .env\nif os.getenv('ASTERIA_SKIP_DOTENV') == '1':\n    env_path = Path('/nonexistent/.env')\ntry:\n    load_dotenv", 1)
    s = s.replace("if not DATABASE_URL:\n    try:\n        txt = (Path(__file__).parent / '.env')",
                  "if not DATABASE_URL and os.getenv('ASTERIA_SKIP_DOTENV') != '1':\n    try:\n        txt = (Path(__file__).parent / '.env')", 1)
    if 'ASTERIA_SKIP_DOTENV' not in s: sys.exit('ANCHOR MISS database.py')
    s = s.replace("engine = create_engine(\n    DATABASE_URL,", "engine = create_engine(\n    DATABASE_URL,\n    **({'connect_args': {'check_same_thread': False}} if DATABASE_URL.startswith('sqlite') else {}),", 1)
    wr('database.py', s); print('patched database.py')
wr('tests/conftest.py', '''"""Test isolation: never touch production .env / MySQL."""
import os
import pathlib
import sys
import tempfile

os.environ["ASTERIA_SKIP_DOTENV"] = "1"
_db = pathlib.Path(tempfile.gettempdir()) / "asteria_test.sqlite"
os.environ["DATABASE_URL"] = "sqlite:///" + str(_db)
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
assert "mysql" not in os.environ["DATABASE_URL"]
''')
wr('pytest.ini', '[pytest]\ntestpaths = tests\naddopts = -q -p no:cacheprovider\n')
wr('requirements-dev.txt', 'pytest==8.3.4\n')
wr('.github/workflows/tests.yml', '''name: tests
on:
  push:
    branches: ["**"]
  pull_request:
jobs:
  pytest:
    runs-on: ubuntu-latest
    env:
      ASTERIA_SKIP_DOTENV: "1"
      DATABASE_URL: "sqlite:////tmp/asteria_ci.sqlite"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: python -m pytest
''')

# 6) deploy.sh (not executed here)
wr('deploy.sh', r'''#!/usr/bin/env bash
# Asteria cloud deploy: ./deploy.sh <git-ref>   (default: origin/main)
# Records previous commit in .deploy/last_good for rollback: ./deploy.sh --rollback
set -euo pipefail
APP_DIR="${APP_DIR:-/data/asteria.run}"
PM2_NAME="${PM2_NAME:-asteria-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:9000/healthz}"
G="git -c safe.directory=$APP_DIR -C $APP_DIR"
mkdir -p "$APP_DIR/.deploy"
if [[ "${1:-}" == "--rollback" ]]; then
  REF="$(cat "$APP_DIR/.deploy/last_good")"; echo "Rolling back to $REF"
else
  REF="${1:-origin/main}"
  if [[ -n "$($G status --porcelain --untracked-files=no)" ]]; then
    echo "ERROR: tracked files modified in $APP_DIR; refusing to deploy" >&2; exit 2
  fi
  $G rev-parse HEAD > "$APP_DIR/.deploy/last_good"
  GIT_SSH_COMMAND='ssh -o BatchMode=yes' $G fetch --quiet origin
fi
OLD_REQ="$($G rev-parse HEAD:requirements.txt 2>/dev/null || true)"
$G checkout --quiet --detach "$REF"
NEW_REQ="$($G rev-parse HEAD:requirements.txt 2>/dev/null || true)"
if [[ -n "$NEW_REQ" && "$OLD_REQ" != "$NEW_REQ" ]]; then
  "$APP_DIR/venv/bin/python" -m pip install -q -r "$APP_DIR/requirements.txt"
fi
pm2 reload "$PM2_NAME" --update-env
for i in $(seq 1 20); do
  sleep 2
  if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null; then
    echo "OK: $($G rev-parse --short HEAD) healthy"; exit 0
  fi
done
echo "ERROR: health check failed after deploy of $REF" >&2
exit 1
''')
wr('deploy/nginx-asteria-logging.conf', '''# Proposed (NOT applied): separate asteria access log with host + timings.
# 1) in http{} (e.g. /etc/nginx/conf.d/asteria-logformat.conf):
log_format asteria_timed '$remote_addr - $remote_user [$time_local] "$host" "$request" '
                         '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                         'rt=$request_time urt=$upstream_response_time cf=$http_cf_connecting_ip';
# 2) inside the asteria.run server{} blocks:
#    access_log /var/log/nginx/asteria.access.log asteria_timed;
#    error_log  /var/log/nginx/asteria.error.log warn;
# 3) nginx -t && systemctl reload nginx   (needs approval; shared server)
''')
print('DONE')
