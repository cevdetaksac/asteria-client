import { useCallback, useEffect, useMemo, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { DataTable, type DataColumn } from '../components/DataTable'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { RowActionMenu } from '../components/RowActionMenu'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type ThreatTab = 'threats' | 'accounts' | 'system' | 'network'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type Attacker = Record<string, unknown>

type LocalUser = {
  username: string
  full_name?: string
  enabled: boolean
  status: string
  protected?: boolean
  is_admin?: boolean
  is_self?: boolean
  groups?: string[]
  last_logon?: string | null
  has_session?: boolean
  session_status?: string | null
  can_enable?: boolean
  can_disable?: boolean
  can_logoff?: boolean
  can_reset_password?: boolean
}

type HardenCheck = {
  id?: string
  label?: string
  ok?: boolean | null
  detail?: string
  fixable?: boolean
}

function formatLogon(value?: string | null): string {
  if (!value) return '—'
  try {
    const d = new Date(value)
    if (Number.isNaN(d.getTime())) return value
    return d.toLocaleString()
  } catch {
    return value
  }
}

function formatThreatTime(value: unknown): string {
  if (value == null || value === '') return '—'
  if (typeof value === 'number') {
    const ms = value > 1e12 ? value : value * 1000
    const d = new Date(ms)
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString()
  }
  return formatLogon(String(value))
}

function normalizeAlertList(payload: unknown): Attacker[] {
  if (Array.isArray(payload)) return payload as Attacker[]
  const rec = asRecord(payload)
  for (const key of ['alerts', 'items', 'results', 'data', 'critical_alerts']) {
    const v = rec[key]
    if (Array.isArray(v)) return v as Attacker[]
  }
  const nested = asRecord(rec.data)
  if (Array.isArray(nested.alerts)) return nested.alerts as Attacker[]
  return []
}

function alertFields(row: Record<string, unknown>) {
  const title = pick(row, 'title', 'name', 'rule_name', 'threat_title')
  const description = pick(row, 'description', 'detail', 'message', 'summary', 'reason')
  const threatType = pick(row, 'threat_type', 'event_type', 'type', 'last_event_type')
  const ip = pick(row, 'source_ip', 'ip', 'src_ip', 'address')
  const score = pick(row, 'threat_score', 'score')
  const when = pick(row, 'timestamp', 'created_at', 'time', 'last_seen')
  const severity = pick(row, 'severity', 'level')
  const service = pick(row, 'target_service', 'service')
  const user = pick(row, 'username', 'user', 'account')
  const action = pick(row, 'recommended_action', 'action')
  return { title, description, threatType, ip, score, when, severity, service, user, action }
}

export function ThreatPage({ onToast }: Props) {
  const [attackers, setAttackers] = useState<Attacker[]>([])
  const [recentAlerts, setRecentAlerts] = useState<Attacker[]>([])
  const [total, setTotal] = useState(0)
  const [users, setUsers] = useState<LocalUser[]>([])
  const [userCounts, setUserCounts] = useState({ total: 0, active: 0, disabled: 0 })
  const [currentUser, setCurrentUser] = useState('')
  const [busy, setBusy] = useState(false)
  const [pwdUser, setPwdUser] = useState<string | null>(null)
  const [pwdValue, setPwdValue] = useState('')
  const [threatTab, setThreatTab] = useState<ThreatTab>('threats')
  const [blockIp, setBlockIp] = useState('')
  const [checks, setChecks] = useState<HardenCheck[]>([])
  const [commands, setCommands] = useState<Array<Record<string, unknown>>>([])
  const [detail, setDetail] = useState<'threat' | 'harden' | null>(null)
  const [pageHelp, setPageHelp] = useState(false)
  const [shares, setShares] = useState<Array<Record<string, unknown>>>([])
  const [shareCustom, setShareCustom] = useState(0)
  const [thirdParty, setThirdParty] = useState<Array<Record<string, unknown>>>([])
  const [svcUnknown, setSvcUnknown] = useState(0)
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [threatsReady, setThreatsReady] = useState(false)
  const [usersReady, setUsersReady] = useState(false)
  const [extrasReady, setExtrasReady] = useState(false)

  const refreshThreats = useCallback(async () => {
    const result = await motorBridge.ipc('THREAT_TOP')
    const list = Array.isArray(result.attackers) ? (result.attackers as Attacker[]) : []
    setAttackers(list)
    setTotal(Number(result.total ?? list.length) || 0)

    const localAlerts = Array.isArray(result.recent_alerts)
      ? (result.recent_alerts as Attacker[])
      : []

    let cloudAlerts: Attacker[] = []
    try {
      const cloud = await motorBridge.cloud('GET', 'alerts/list', { limit: 40 })
      if (cloud.ok) cloudAlerts = normalizeAlertList(cloud.data)
    } catch {
      cloudAlerts = []
    }

    // Prefer cloud (dashboard SoT) when present; else motor ring.
    const merged = cloudAlerts.length > 0 ? cloudAlerts : localAlerts
    setRecentAlerts(merged.slice(0, 40))
    setThreatsReady(true)
  }, [])

  const refreshUsers = useCallback(async () => {
    const result = await motorBridge.ir('list')
    if (!result.ok) {
      setUsersReady(true)
      onToast(String(result.error || t('threat_users_load_fail')), 'err')
      return
    }
    const list = Array.isArray(result.users) ? (result.users as LocalUser[]) : []
    setUsers(list)
    const counts = asRecord(result.counts)
    setUserCounts({
      total: Number(counts.total ?? list.length) || 0,
      active: Number(counts.active ?? list.filter((u) => u.enabled).length) || 0,
      disabled: Number(counts.disabled ?? list.filter((u) => !u.enabled).length) || 0,
    })
    setCurrentUser(String(result.current_user || ''))
    setUsersReady(true)
  }, [onToast])

  const refreshExtras = useCallback(async () => {
    const [h, status, sh, sv, cloud] = await Promise.all([
      motorBridge.harden('status'),
      motorBridge.status() as Promise<MotorStatus>,
      motorBridge.ipc('SHARES_LIST'),
      motorBridge.ipc('SVC_LIST'),
      motorBridge.cloud('GET', 'threats/config'),
    ])
    if (h.ok && Array.isArray(h.checks)) setChecks(h.checks as HardenCheck[])
    const recent = Array.isArray(status.commands_recent)
      ? (status.commands_recent as Array<Record<string, unknown>>)
      : []
    setCommands(recent)
    if (sh.ok && Array.isArray(sh.shares)) {
      setShares(sh.shares as Array<Record<string, unknown>>)
      setShareCustom(Number(sh.custom_count || 0) || 0)
    }
    if (sv.ok && Array.isArray(sv.services)) {
      setThirdParty(sv.services as Array<Record<string, unknown>>)
      setSvcUnknown(Number(sv.unknown_count || 0) || 0)
    }
    if (cloud.ok && cloud.data && typeof cloud.data === 'object') {
      const wl = (cloud.data as Record<string, unknown>).whitelist_ips
      if (Array.isArray(wl)) setWhitelist(wl.map(String).filter(Boolean))
    }
    setExtrasReady(true)
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshThreats(), refreshUsers(), refreshExtras()])
  }, [refreshThreats, refreshUsers, refreshExtras])

  useEffect(() => {
    void refreshAll()
    const timer = window.setInterval(() => void refreshAll(), 10000)
    return () => window.clearInterval(timer)
  }, [refreshAll])

  const sessions = useMemo(() => users.filter((u) => u.has_session), [users])
  const logoffable = useMemo(() => {
    const map = new Map<string, LocalUser>()
    for (const u of users) {
      if (u.can_logoff) map.set(u.username.toLowerCase(), u)
    }
    return map
  }, [users])
  const canLogoffUser = useCallback(
    (name: string) => {
      const key = String(name || '').trim().toLowerCase()
      if (!key || key === '—') return false
      return logoffable.has(key)
    },
    [logoffable],
  )
  const warnCount = useMemo(() => checks.filter((c) => c.ok === false).length, [checks])

  /** Cloud alerts + motor attackers — one list, dedupe by IP (alerts win). */
  const threatRows = useMemo(() => {
    const seen = new Set<string>()
    const out: Attacker[] = []
    for (const row of recentAlerts) {
      const ip = alertFields(asRecord(row)).ip
      if (ip !== '—') seen.add(ip.toLowerCase())
      out.push(row)
    }
    for (const row of attackers) {
      const r = asRecord(row)
      const ip = pick(r, 'ip', 'source_ip')
      const key = ip !== '—' ? ip.toLowerCase() : ''
      if (key && seen.has(key)) continue
      if (key) seen.add(key)
      out.push({
        ...r,
        title: r.title ?? r.threat_type ?? r.type,
        description: r.description ?? r.detail ?? r.reason,
        source_ip: r.source_ip ?? r.ip,
        threat_score: r.threat_score ?? r.score,
        timestamp: r.timestamp ?? r.last_seen ?? r.created_at,
        severity: r.severity ?? (Number(r.threat_score ?? r.score) >= 80 ? 'high' : 'medium'),
      })
    }
    return out
  }, [recentAlerts, attackers])

  const block = async (ip: string) => {
    if (!ip || ip === '—') return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('BLOCK_IP', { ip, reason: 'threat_center' })
      onToast(result.ok ? t('toast_blocked', { ip }) : String(result.error || 'Block'), result.ok ? 'ok' : 'err')
      setBlockIp('')
      await refreshThreats()
    } finally {
      setBusy(false)
    }
  }

  const unblock = async (ip: string) => {
    if (!ip || ip === '—') return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('UNBLOCK_IP', { ip, reason: 'threat_center' })
      onToast(
        result.ok ? t('toast_unblocked', { ip }) : String(result.error || 'Unblock'),
        result.ok ? 'ok' : 'err',
      )
      await refreshThreats()
    } finally {
      setBusy(false)
    }
  }

  const addWhitelist = async (ip: string) => {
    if (!ip || ip === '—') return
    if (whitelist.includes(ip)) {
      onToast(t('toast_wl_ok'), 'ok')
      return
    }
    setBusy(true)
    try {
      const next = [...whitelist, ip]
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      if (result.ok) setWhitelist(next)
    } finally {
      setBusy(false)
    }
  }

  const snapshot = async () => {
    setBusy(true)
    try {
      const result = await motorBridge.ipc('NG_SNAPSHOT')
      onToast(result.ok ? t('toast_snapshot') : String(result.error || 'Snapshot'), result.ok ? 'ok' : 'err')
    } finally {
      setBusy(false)
    }
  }

  const fixHarden = async (target: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.harden('fix', target)
      onToast(result.ok ? t('toast_harden_ok') : String(result.error || 'harden'), result.ok ? 'ok' : 'err')
      await refreshExtras()
    } finally {
      setBusy(false)
    }
  }

  const removeShare = async (name: string) => {
    if (!name) return
    if (!window.confirm(t('threat_share_confirm', { name }))) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('SHARE_REMOVE', { name })
      onToast(
        result.ok ? t('toast_share_removed', { name }) : String(result.error || 'SHARE_REMOVE'),
        result.ok ? 'ok' : 'err',
      )
      await refreshExtras()
    } finally {
      setBusy(false)
    }
  }

  const stopService = async (name: string, display?: string) => {
    if (!name) return
    if (!window.confirm(t('threat_svc_confirm', { name: display || name }))) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('SVC_STOP', { name })
      onToast(
        result.ok ? t('toast_svc_stopped', { name: display || name }) : String(result.error || 'SVC_STOP'),
        result.ok ? 'ok' : 'err',
      )
      await refreshExtras()
    } finally {
      setBusy(false)
    }
  }

  const runIr = async (
    action: 'logoff' | 'disable' | 'enable' | 'reset_password',
    username: string,
    newPassword = '',
  ) => {
    const user = username.trim()
    if (!user) {
      onToast(t('threat_need_user'), 'err')
      return
    }
    if (action === 'logoff' && !window.confirm(t('threat_confirm_logoff', { user }))) return
    if (action === 'disable' && !window.confirm(t('threat_confirm_disable', { user }))) return
    if (action === 'enable' && !window.confirm(t('threat_confirm_enable', { user }))) return
    if (action === 'reset_password') {
      if (newPassword.length < 8) {
        onToast(t('threat_pwd_short'), 'err')
        return
      }
      if (!window.confirm(t('threat_confirm_password', { user }))) return
    }

    setBusy(true)
    try {
      const result = await motorBridge.ir(action, user, newPassword)
      if (!result.ok) {
        const err = String(result.error || 'IR')
        onToast(
          err === 'self_account'
            ? t('threat_self_blocked')
            : err === 'LAST_ADMIN'
              ? t('threat_last_admin')
              : err,
          'err',
        )
        return
      }
      const toastKey =
        action === 'logoff'
          ? 'toast_logoff_ok'
          : action === 'disable'
            ? 'toast_disable_ok'
            : action === 'enable'
              ? 'toast_enable_ok'
              : 'toast_password_ok'
      onToast(t(toastKey, { user }), 'ok')
      setPwdUser(null)
      setPwdValue('')
      await refreshUsers()
    } finally {
      setBusy(false)
    }
  }


  const alertColumns = useMemo<DataColumn<Attacker>[]>(() => [
    {
      id: 'time',
      header: t('threat_col_time'),
      className: 'threat-time muted',
      searchText: (row) => formatThreatTime(alertFields(asRecord(row)).when === '—' ? null : alertFields(asRecord(row)).when),
      cell: (row) => {
        const f = alertFields(asRecord(row))
        return formatThreatTime(f.when === '—' ? null : f.when)
      },
    },
    {
      id: 'threat',
      header: t('threat_col_threat'),
      className: 'threat-detail-cell',
      searchText: (row) => {
        const f = alertFields(asRecord(row))
        return `${f.title} ${f.description} ${f.threatType} ${f.severity} ${f.service}`
      },
      cell: (row) => {
        const f = alertFields(asRecord(row))
        return (
          <>
            <strong className="threat-detail-title">{f.title !== '—' ? f.title : f.threatType}</strong>
            {f.description !== '—' && <p className="threat-detail-desc">{f.description}</p>}
            <div className="threat-detail-meta">
              {f.threatType !== '—' && <span className="pill muted">{f.threatType}</span>}
              {f.severity !== '—' && (
                <span className={`pill ${f.severity === 'critical' || f.severity === 'high' ? 'danger' : 'muted'}`}>{f.severity}</span>
              )}
              {f.service !== '—' && <span className="pill muted">{f.service}</span>}
              {f.action !== '—' && <span className="muted threat-action-hint">{f.action}</span>}
            </div>
          </>
        )
      },
    },
    {
      id: 'source',
      header: t('threat_col_source'),
      className: 'mono',
      searchText: (row) => {
        const f = alertFields(asRecord(row))
        return `${f.ip} ${f.user}`
      },
      cell: (row) => {
        const f = alertFields(asRecord(row))
        return (
          <>
            {f.ip}
            {f.user !== '—' ? <div className="muted">{f.user}</div> : null}
          </>
        )
      },
    },
    {
      id: 'score',
      header: t('threat_col_score'),
      searchText: (row) => String(alertFields(asRecord(row)).score),
      cell: (row) => {
        const f = alertFields(asRecord(row))
        return <span className={`score-pill ${Number(f.score) >= 80 ? 'high' : ''}`}>{f.score}</span>
      },
    },
    {
      id: 'actions',
      header: t('threat_col_actions'),
      headerClassName: 'actions-head',
      className: 'actions-cell',
      cell: (row) => {
        const f = alertFields(asRecord(row))
        const ip = f.ip
        const primary = ip !== '—'
          ? [{ id: 'block', label: t('btn_block'), danger: true, disabled: busy, onClick: () => void block(ip) }]
          : []
        const more = []
        if (ip !== '—') {
          more.push(
            { id: 'unblock', label: t('btn_unblock'), disabled: busy, onClick: () => void unblock(ip) },
            { id: 'wl', label: t('btn_whitelist_add'), disabled: busy || whitelist.includes(ip), onClick: () => void addWhitelist(ip) },
          )
        }
        if (canLogoffUser(f.user)) {
          more.push({ id: 'logoff', label: t('threat_logoff'), disabled: busy, onClick: () => void runIr('logoff', f.user) })
        }
        if (f.user !== '—' && f.user.toLowerCase() !== currentUser.toLowerCase()) {
          more.push({ id: 'disable', label: t('threat_disable'), danger: true, disabled: busy, onClick: () => void runIr('disable', f.user) })
        }
        return <RowActionMenu primary={primary} more={more} />
      },
    },
  ], [busy, whitelist, currentUser, canLogoffUser])

  const userColumns = useMemo<DataColumn<LocalUser>[]>(() => [
    {
      id: 'user',
      header: t('threat_col_user'),
      searchText: (u) => `${u.username} ${u.full_name || ''}`,
      cell: (u) => (
        <>
          <div className="account-name">
            <strong className="mono">{u.username}</strong>
            {u.is_self && <span className="pill self">{t('threat_badge_you')}</span>}
            {u.is_admin && <span className="pill admin">{t('threat_badge_admin')}</span>}
            {u.protected && <span className="pill muted">{t('threat_badge_protected')}</span>}
          </div>
          {u.full_name ? <small className="muted">{u.full_name}</small> : null}
        </>
      ),
    },
    {
      id: 'status',
      header: t('threat_col_status'),
      searchText: (u) => (u.enabled ? 'active' : 'disabled'),
      cell: (u) => (
        <span className={`pill ${u.enabled ? 'ok' : 'off'}`}>
          {u.enabled ? t('threat_status_active') : t('threat_status_disabled')}
        </span>
      ),
    },
    {
      id: 'groups',
      header: t('threat_col_groups'),
      className: 'muted',
      searchText: (u) => (u.groups || []).join(' '),
      cell: (u) => (u.groups || []).join(', ') || '—',
    },
    {
      id: 'session',
      header: t('threat_col_session'),
      className: 'muted',
      cell: (u) => (u.has_session ? (u.session_status || t('threat_session_yes')) : t('threat_session_no')),
    },
    {
      id: 'last',
      header: t('threat_col_last_logon'),
      className: 'muted mono',
      cell: (u) => formatLogon(u.last_logon),
    },
    {
      id: 'actions',
      header: t('threat_col_actions'),
      headerClassName: 'actions-head',
      className: 'actions-cell',
      cell: (u) => (
        <>
          <RowActionMenu
            primary={[
              ...(u.can_logoff
                ? [{ id: 'logoff', label: t('threat_logoff'), disabled: busy, onClick: () => void runIr('logoff', u.username) }]
                : u.can_disable
                  ? [{ id: 'disable', label: t('threat_disable'), danger: true, disabled: busy, onClick: () => void runIr('disable', u.username) }]
                  : u.can_enable
                    ? [{ id: 'enable', label: t('threat_enable'), disabled: busy, onClick: () => void runIr('enable', u.username) }]
                    : []),
            ]}
            more={[
              ...(u.can_logoff && u.can_disable
                ? [{ id: 'disable', label: t('threat_disable'), danger: true, disabled: busy, onClick: () => void runIr('disable', u.username) }]
                : []),
              ...(u.can_enable && u.can_logoff
                ? [{ id: 'enable', label: t('threat_enable'), disabled: busy, onClick: () => void runIr('enable', u.username) }]
                : []),
              ...(u.can_reset_password
                ? [{
                    id: 'pwd',
                    label: t('threat_password'),
                    disabled: busy,
                    onClick: () => {
                      setPwdUser(u.username)
                      setPwdValue('')
                    },
                  }]
                : []),
            ]}
          />
          {pwdUser === u.username && (
            <div className="inline-form pwd-row">
              <input
                type="password"
                autoComplete="new-password"
                placeholder={t('threat_pwd_ph')}
                value={pwdValue}
                onChange={(e) => setPwdValue(e.target.value)}
              />
              <button
                type="button"
                className="btn sm"
                disabled={busy}
                onClick={() => void runIr('reset_password', u.username, pwdValue)}
              >
                {t('btn_apply')}
              </button>
              <button
                type="button"
                className="btn ghost sm"
                disabled={busy}
                onClick={() => {
                  setPwdUser(null)
                  setPwdValue('')
                }}
              >
                {t('btn_cancel')}
              </button>
            </div>
          )}
        </>
      ),
    },
  ], [busy, pwdUser, pwdValue])


  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('threat_eyebrow')}</p>
          <h2>{t('threat_title')}</h2>
          <p className="muted">{t('threat_blurb')}</p>
        </div>
        <div className="btn-row">
          <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
            {t('help_more')}
          </button>
          <button type="button" className="btn ghost" disabled={busy} onClick={() => void snapshot()}>
            {t('btn_snapshot')}
          </button>
          <button type="button" className="btn" onClick={() => void refreshAll()}>{t('btn_refresh')}</button>
        </div>
      </div>

      <div className="cards three">
        <article className="clickable" onClick={() => setDetail('threat')}>
          <p>{t('threat_card_listed')}</p>
          <strong>{threatRows.length}</strong>
          <small>{t('threat_card_listed_meta')}</small>
        </article>
        <article className="clickable" onClick={() => setDetail('threat')}>
          <p>{t('threat_card_context')}</p>
          <strong>{total}</strong>
          <small>{t('threat_card_context_meta')}</small>
        </article>
        <article className="clickable" onClick={() => setDetail('harden')}>
          <p>{t('threat_card_harden')}</p>
          <strong className={warnCount ? 'bad' : ''}>{warnCount}</strong>
          <small>{t('threat_card_harden_meta')}</small>
        </article>
      </div>

      <div className="quick-actions">
        <form
          className="inline-form"
          style={{ margin: 0 }}
          onSubmit={(e) => {
            e.preventDefault()
            void block(blockIp.trim())
          }}
        >
          <input
            className="mono"
            value={blockIp}
            onChange={(e) => setBlockIp(e.target.value)}
            placeholder={t('threat_block_ip_ph')}
            aria-label={t('threat_block_ip_ph')}
          />
          <button type="submit" className="btn danger sm" disabled={busy || !blockIp.trim()}>
            {t('btn_block')}
          </button>
        </form>
        <button type="button" className="btn ghost sm" disabled={busy || sessions.length === 0} onClick={() => {
          const first = sessions.find((u) => u.can_logoff)
          if (first) void runIr('logoff', first.username)
        }}>
          {t('threat_quick_logoff')}
        </button>
        <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void snapshot()}>
          {t('btn_snapshot')}
        </button>
      </div>

      <nav className="page-tabs" aria-label={t('threat_title')}>
        {(
          [
            ['threats', t('threat_tab_threats'), threatRows.length],
            ['accounts', t('threat_tab_accounts'), users.length],
            ['system', t('threat_tab_system'), warnCount],
            ['network', t('threat_tab_network'), shares.length + thirdParty.length],
          ] as Array<[ThreatTab, string, number]>
        ).map(([id, label, count]) => (
          <button
            key={id}
            type="button"
            className={`page-tab${threatTab === id ? ' active' : ''}`}
            onClick={() => setThreatTab(id)}
          >
            {label}
            <span className="tab-count">{count}</span>
          </button>
        ))}
      </nav>

      {threatTab === 'threats' && (
        <article className="panel panel-spaced">
          <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
            <div>
              <p className="eyebrow">{t('threat_alerts_eyebrow')}</p>
              <h3>
                {t('threat_alerts_title')}
                {threatRows.length > 0 ? <span className="pill danger threat-count-pill">{threatRows.length}</span> : null}
                {!threatsReady && <span className="inline-spinner" />}
              </h3>
              <p className="muted">{t('threat_alerts_blurb')}</p>
            </div>
            <button type="button" className="btn ghost sm" onClick={() => void motorBridge.shell('open_dashboard', 'dash_threats')}>
              {t('threat_alerts_all')}
            </button>
          </div>
          <DataTable
            rows={threatRows}
            rowKey={(row, idx) => {
              const r = asRecord(row)
              const f = alertFields(r)
              return `${f.ip}-${f.when}-${idx}`
            }}
            empty={threatsReady ? t('threat_alerts_empty') : t('label_loading')}
            tableClassName="threat-rich-table"
            defaultPageSize={25}
            columns={alertColumns}
          />
        </article>
      )}

      {threatTab === 'system' && (
        <>
          <article className="panel panel-spaced">
            <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
              <div>
                <p className="eyebrow">{t('threat_harden_eyebrow')}</p>
                <h3>{t('threat_harden_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
                <p className="muted">
                  {warnCount > 0
                    ? t('threat_harden_warn', { count: warnCount })
                    : t('threat_harden_ok')}
                </p>
              </div>
            </div>
            <div className="check-list">
              {extrasReady && checks.length === 0 && (
                <p className="muted">{t('status_harden_loading')}</p>
              )}
              {checks.map((c) => (
                <div key={String(c.id || c.label)} className="check-row">
                  <div>
                    <strong className={c.ok === false ? 'bad' : c.ok ? 'good' : ''}>{c.label}</strong>
                    <p className="muted">{c.detail}</p>
                  </div>
                  {c.fixable && c.id && (
                    <button type="button" className="btn sm" disabled={busy} onClick={() => void fixHarden(String(c.id))}>
                      {t('btn_fix')}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </article>

          <div className="split split-stack" style={{ marginBottom: 18 }}>
            <article className="panel">
              <p className="eyebrow">{t('threat_sessions_eyebrow')}</p>
              <h3>{t('threat_sessions_title')}{!usersReady && <span className="inline-spinner" />}</h3>
              <DataTable
                rows={sessions}
                rowKey={(u) => `s-${u.username}`}
                empty={usersReady ? t('threat_sessions_empty') : t('label_loading')}
                searchable={sessions.length > 8}
                defaultPageSize={10}
                columns={[
                  {
                    id: 'user',
                    header: t('threat_col_user'),
                    className: 'mono',
                    searchText: (u) => u.username,
                    cell: (u) => u.username,
                  },
                  {
                    id: 'session',
                    header: t('threat_col_session'),
                    className: 'muted',
                    cell: (u) => u.session_status || t('threat_session_yes'),
                  },
                  {
                    id: 'actions',
                    header: t('threat_col_actions'),
                    headerClassName: 'actions-head',
                    className: 'actions-cell',
                    cell: (u) => (
                      <RowActionMenu
                        primary={u.can_logoff ? [{ id: 'logoff', label: t('threat_logoff'), onClick: () => void runIr('logoff', u.username), disabled: busy }] : []}
                        more={[
                          ...(u.can_disable
                            ? [{ id: 'disable', label: t('threat_disable'), danger: true as const, onClick: () => void runIr('disable', u.username), disabled: busy }]
                            : []),
                        ]}
                      />
                    ),
                  },
                ]}
              />
            </article>

            <article className="panel">
              <div className="page-head" style={{ marginBottom: 8, paddingBottom: 0, border: 'none' }}>
                <div>
                  <p className="eyebrow">{t('threat_cmd_eyebrow')}</p>
                  <h3>{t('threat_cmd_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
                </div>
                <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void refreshExtras()}>
                  {t('btn_refresh')}
                </button>
              </div>
              <DataTable
                rows={commands}
                rowKey={(row, idx) => `${pick(asRecord(row), 'command', 'cmd', 'type', 'name')}-${idx}`}
                empty={extrasReady ? t('threat_cmd_empty') : t('label_loading')}
                searchable={commands.length > 8}
                defaultPageSize={10}
                columns={[
                  {
                    id: 'cmd',
                    header: t('threat_cmd_col'),
                    className: 'mono',
                    searchText: (row) => pick(asRecord(row), 'command', 'cmd', 'type', 'name'),
                    cell: (row) => pick(asRecord(row), 'command', 'cmd', 'type', 'name'),
                  },
                  {
                    id: 'status',
                    header: t('threat_cmd_status'),
                    className: 'muted',
                    searchText: (row) => pick(asRecord(row), 'status', 'state', 'result'),
                    cell: (row) => pick(asRecord(row), 'status', 'state', 'result'),
                  },
                ]}
              />
            </article>
          </div>
        </>
      )}

      {threatTab === 'network' && (
        <div className="split split-stack" style={{ marginBottom: 18 }}>
          <article className="panel">
            <p className="eyebrow">{t('threat_shares_eyebrow')}</p>
            <h3>{t('threat_shares_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
            <p className="muted">
              {shareCustom > 0
                ? t('threat_shares_custom', { count: shareCustom })
                : t('threat_shares_default_only')}
            </p>
            <DataTable
              rows={shares}
              rowKey={(row) => `share-${String(asRecord(row).name || '')}`}
              empty={extrasReady ? t('threat_shares_empty') : t('label_loading')}
              defaultPageSize={10}
              columns={[
                {
                  id: 'name',
                  header: t('threat_shares_col_name'),
                  searchText: (row) => String(asRecord(row).name || ''),
                  cell: (row) => {
                    const r = asRecord(row)
                    const name = String(r.name || '')
                    const isDefault = Boolean(r.is_default)
                    const usersN = Number(r.current_users || 0) || 0
                    return (
                      <>
                        <strong className={`mono ${isDefault ? 'muted' : ''}`}>{name}</strong>
                        {usersN > 0 && (
                          <small className="muted"> · {t('threat_shares_users', { count: usersN })}</small>
                        )}
                      </>
                    )
                  },
                },
                {
                  id: 'path',
                  header: t('threat_shares_col_path'),
                  className: 'muted',
                  searchText: (row) => String(asRecord(row).path || asRecord(row).description || ''),
                  cell: (row) => String(asRecord(row).path || asRecord(row).description || '—'),
                },
                {
                  id: 'actions',
                  header: t('threat_col_actions'),
                  headerClassName: 'actions-head',
                  className: 'actions-cell',
                  cell: (row) => {
                    const r = asRecord(row)
                    const name = String(r.name || '')
                    if (r.is_default) return <span className="muted" style={{ fontSize: 11 }}>—</span>
                    return (
                      <RowActionMenu
                        primary={[{ id: 'rm', label: t('threat_shares_remove'), danger: true, disabled: busy, onClick: () => void removeShare(name) }]}
                      />
                    )
                  },
                },
              ]}
            />
          </article>

          <article className="panel">
            <p className="eyebrow">{t('threat_svc_eyebrow')}</p>
            <h3>{t('threat_svc_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
            <p className="muted">
              {svcUnknown > 0
                ? t('threat_svc_unknown', { count: svcUnknown })
                : t('threat_svc_clean')}
            </p>
            <DataTable
              rows={thirdParty}
              rowKey={(row) => `svc-${String(asRecord(row).name || '')}`}
              empty={extrasReady ? t('threat_svc_empty') : t('label_loading')}
              defaultPageSize={10}
              columns={[
                {
                  id: 'name',
                  header: t('threat_svc_col_name'),
                  searchText: (row) => `${asRecord(row).display || ''} ${asRecord(row).name || ''}`,
                  cell: (row) => {
                    const r = asRecord(row)
                    const name = String(r.name || '')
                    const display = String(r.display || name)
                    return (
                      <>
                        <strong>{display}</strong>
                        <div className="mono muted" style={{ fontSize: 11 }}>{name}</div>
                        {Boolean(r.known) && <span className="pill muted">{t('threat_svc_known')}</span>}
                      </>
                    )
                  },
                },
                {
                  id: 'path',
                  header: t('threat_svc_col_path'),
                  className: 'muted',
                  searchText: (row) => String(asRecord(row).path || ''),
                  cell: (row) => (
                    <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{String(asRecord(row).path || '—')}</span>
                  ),
                },
                {
                  id: 'actions',
                  header: t('threat_col_actions'),
                  headerClassName: 'actions-head',
                  className: 'actions-cell',
                  cell: (row) => {
                    const r = asRecord(row)
                    const name = String(r.name || '')
                    const display = String(r.display || name)
                    if (r.known) return <span className="muted" style={{ fontSize: 11 }}>{t('threat_svc_known')}</span>
                    return (
                      <RowActionMenu
                        primary={[{ id: 'stop', label: t('threat_svc_stop'), danger: true, disabled: busy, onClick: () => void stopService(name, display) }]}
                      />
                    )
                  },
                },
              ]}
            />
          </article>
        </div>
      )}

      {threatTab === 'accounts' && (
      <div className="accordion open">
        <div className="accordion-trigger" aria-expanded={true}>
          <div>
            <p className="eyebrow">{t('threat_ir_eyebrow')}</p>
            <h3>{t('threat_users_title')}{!usersReady && <span className="inline-spinner" />}</h3>
            <p className="muted">
              {t('threat_card_accounts_meta', {
                active: userCounts.active,
                disabled: userCounts.disabled,
              })}
              {currentUser ? ` · ${t('threat_you_are', { user: currentUser })}` : ''}
            </p>
          </div>
        </div>
        <div className="accordion-body">
          <p className="muted" style={{ marginBottom: 12 }}>{t('threat_users_blurb')}</p>
          <DataTable
            rows={users}
            rowKey={(u) => u.username}
            empty={usersReady ? t('threat_users_empty') : t('label_loading')}
            tableClassName="accounts-table"
            defaultPageSize={25}
            columns={userColumns}
          />
        </div>
      </div>
      )}

      {detail === 'threat' && (
        <DetailModal
          title={t('threat_alerts_title')}
          eyebrow={t('threat_alerts_eyebrow')}
          blurb={t('threat_alerts_blurb')}
          rows={[
            { label: t('threat_card_listed'), value: String(threatRows.length) },
            { label: t('threat_card_context'), value: String(total) },
            {
              label: t('threat_detail_top_score'),
              value: threatRows.length
                ? String(alertFields(asRecord(threatRows[0])).score)
                : '—',
            },
          ]}
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'harden' && (
        <DetailModal
          title={t('threat_harden_title')}
          eyebrow={t('threat_harden_eyebrow')}
          blurb={warnCount > 0 ? t('threat_harden_warn', { count: warnCount }) : t('threat_harden_ok')}
          rows={checks.slice(0, 12).map((c) => ({
            label: String(c.label || c.id || '—'),
            value: c.ok === false ? t('label_off') : c.ok ? t('label_ok') : '—',
            tone: c.ok === false ? 'bad' : c.ok ? 'ok' : 'plain',
          }))}
          onClose={() => setDetail(null)}
        />
      )}
      {pageHelp && (
        <DetailModal
          title={t('threat_title')}
          eyebrow={t('threat_eyebrow')}
          blurb={t('threat_blurb')}
          guide={<FeatureGuide prefix="help_threat" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
