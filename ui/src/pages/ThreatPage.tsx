import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { IconBtn, icons } from '../components/IconBtn'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

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

export function ThreatPage({ onToast }: Props) {
  const [attackers, setAttackers] = useState<Attacker[]>([])
  const [total, setTotal] = useState(0)
  const [users, setUsers] = useState<LocalUser[]>([])
  const [userCounts, setUserCounts] = useState({ total: 0, active: 0, disabled: 0 })
  const [currentUser, setCurrentUser] = useState('')
  const [busy, setBusy] = useState(false)
  const [pwdUser, setPwdUser] = useState<string | null>(null)
  const [pwdValue, setPwdValue] = useState('')
  const [accountsOpen, setAccountsOpen] = useState(false)
  const [blockIp, setBlockIp] = useState('')
  const [checks, setChecks] = useState<HardenCheck[]>([])
  const [commands, setCommands] = useState<Array<Record<string, unknown>>>([])
  const [detail, setDetail] = useState<'threat' | 'harden' | null>(null)
  const [pageHelp, setPageHelp] = useState(false)
  const [shares, setShares] = useState<Array<Record<string, unknown>>>([])
  const [shareCustom, setShareCustom] = useState(0)
  const [thirdParty, setThirdParty] = useState<Array<Record<string, unknown>>>([])
  const [svcUnknown, setSvcUnknown] = useState(0)

  const refreshThreats = useCallback(async () => {
    const result = await motorBridge.ipc('THREAT_TOP')
    const list = Array.isArray(result.attackers) ? (result.attackers as Attacker[]) : []
    setAttackers(list)
    setTotal(Number(result.total ?? list.length) || 0)
  }, [])

  const refreshUsers = useCallback(async () => {
    const result = await motorBridge.ir('list')
    if (!result.ok) {
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
  }, [onToast])

  const refreshExtras = useCallback(async () => {
    const [h, status, sh, sv] = await Promise.all([
      motorBridge.harden('status'),
      motorBridge.status() as Promise<MotorStatus>,
      motorBridge.ipc('SHARES_LIST'),
      motorBridge.ipc('SVC_LIST'),
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
  const warnCount = useMemo(() => checks.filter((c) => c.ok === false).length, [checks])

  const block = async (ip: string) => {
    if (!ip) return
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
          <strong>{attackers.length}</strong>
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

      <article className="panel" style={{ marginBottom: 18 }}>
        <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
          <div>
            <p className="eyebrow">{t('threat_attackers_eyebrow')}</p>
            <h3>{t('threat_attackers_title')}</h3>
            <p className="muted">{t('threat_attackers_blurb')}</p>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('threat_col_ip')}</th>
                <th>{t('threat_col_score')}</th>
                <th>{t('threat_col_events')}</th>
                <th>{t('threat_col_last')}</th>
                <th className="actions-head">{t('threat_col_actions')}</th>
              </tr>
            </thead>
            <tbody>
              {attackers.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">{t('threat_empty')}</td>
                </tr>
              )}
              {attackers.map((row) => {
                const r = asRecord(row)
                const ip = pick(r, 'ip', 'src_ip', 'address')
                const user = pick(r, 'username', 'user', 'account')
                return (
                  <tr key={ip + pick(r, 'score', 'last_seen')}>
                    <td className="mono">{ip}{user !== '—' ? ` · ${user}` : ''}</td>
                    <td>{pick(r, 'score', 'threat_score')}</td>
                    <td>{pick(r, 'events', 'event_count', 'count')}</td>
                    <td>{pick(r, 'last_seen', 'updated_at')}</td>
                    <td className="actions-cell">
                      <div className="ip-row-actions">
                        <IconBtn
                          icon={icons.block}
                          title={t('btn_block')}
                          danger
                          disabled={busy || ip === '—'}
                          onClick={() => void block(ip)}
                        />
                        {user !== '—' && user.toLowerCase() !== currentUser.toLowerCase() && (
                          <>
                            <IconBtn
                              icon={icons.logoff}
                              title={t('threat_logoff')}
                              disabled={busy}
                              onClick={() => void runIr('logoff', user)}
                            />
                            <IconBtn
                              icon={icons.disable}
                              title={t('threat_disable')}
                              danger
                              disabled={busy}
                              onClick={() => void runIr('disable', user)}
                            />
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </article>

      <article className="panel" style={{ marginBottom: 18 }}>
        <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
          <div>
            <p className="eyebrow">{t('threat_harden_eyebrow')}</p>
            <h3>{t('threat_harden_title')}</h3>
            <p className="muted">
              {warnCount > 0
                ? t('threat_harden_warn', { count: warnCount })
                : t('threat_harden_ok')}
            </p>
          </div>
        </div>
        <div className="check-list">
          {checks.length === 0 && <p className="muted">{t('status_harden_loading')}</p>}
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

      <div className="split" style={{ marginBottom: 18 }}>
        <article className="panel">
          <p className="eyebrow">{t('threat_shares_eyebrow')}</p>
          <h3>{t('threat_shares_title')}</h3>
          <p className="muted">
            {shareCustom > 0
              ? t('threat_shares_custom', { count: shareCustom })
              : t('threat_shares_default_only')}
          </p>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>{t('threat_shares_col_name')}</th>
                  <th>{t('threat_shares_col_path')}</th>
                  <th className="actions-head">{t('threat_col_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {shares.length === 0 && (
                  <tr><td colSpan={3} className="empty">{t('threat_shares_empty')}</td></tr>
                )}
                {shares.map((row) => {
                  const r = asRecord(row)
                  const name = String(r.name || '')
                  const isDefault = Boolean(r.is_default)
                  const users = Number(r.current_users || 0) || 0
                  const path = String(r.path || r.description || '—')
                  return (
                    <tr key={`share-${name}`}>
                      <td>
                        <strong className={`mono ${isDefault ? 'muted' : ''}`}>{name}</strong>
                        {users > 0 && (
                          <small className="muted"> · {t('threat_shares_users', { count: users })}</small>
                        )}
                      </td>
                      <td className="muted">{path}</td>
                      <td className="actions-cell">
                        {!isDefault && (
                          <IconBtn
                            icon={icons.removeWhitelist}
                            title={t('threat_shares_remove')}
                            danger
                            disabled={busy}
                            onClick={() => void removeShare(name)}
                          />
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </article>

        <article className="panel">
          <p className="eyebrow">{t('threat_svc_eyebrow')}</p>
          <h3>{t('threat_svc_title')}</h3>
          <p className="muted">
            {svcUnknown > 0
              ? t('threat_svc_unknown', { count: svcUnknown })
              : t('threat_svc_clean')}
          </p>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>{t('threat_svc_col_name')}</th>
                  <th>{t('threat_svc_col_path')}</th>
                  <th className="actions-head">{t('threat_col_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {thirdParty.length === 0 && (
                  <tr><td colSpan={3} className="empty">{t('threat_svc_empty')}</td></tr>
                )}
                {thirdParty.map((row) => {
                  const r = asRecord(row)
                  const name = String(r.name || '')
                  const display = String(r.display || name)
                  const known = Boolean(r.known)
                  return (
                    <tr key={`svc-${name}`}>
                      <td>
                        <strong>{display}</strong>
                        <div className="mono muted" style={{ fontSize: 11 }}>{name}</div>
                        {known && <span className="pill muted">{t('threat_svc_known')}</span>}
                      </td>
                      <td className="muted" style={{ fontSize: 11, wordBreak: 'break-all' }}>
                        {String(r.path || '—')}
                      </td>
                      <td className="actions-cell">
                        {!known && (
                          <IconBtn
                            icon={icons.disable}
                            title={t('threat_svc_stop')}
                            danger
                            disabled={busy}
                            onClick={() => void stopService(name, display)}
                          />
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </article>
      </div>

      <div className="split" style={{ marginBottom: 18 }}>
        <article className="panel">
          <p className="eyebrow">{t('threat_sessions_eyebrow')}</p>
          <h3>{t('threat_sessions_title')}</h3>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>{t('threat_col_user')}</th>
                  <th>{t('threat_col_session')}</th>
                  <th className="actions-head">{t('threat_col_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 && (
                  <tr><td colSpan={3} className="empty">{t('threat_sessions_empty')}</td></tr>
                )}
                {sessions.map((u) => (
                  <tr key={`s-${u.username}`}>
                    <td className="mono">{u.username}</td>
                    <td className="muted">{u.session_status || t('threat_session_yes')}</td>
                    <td className="actions-cell">
                      {u.can_logoff && (
                        <IconBtn
                          icon={icons.logoff}
                          title={t('threat_logoff')}
                          disabled={busy}
                          onClick={() => void runIr('logoff', u.username)}
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <article className="panel">
          <p className="eyebrow">{t('threat_cmd_eyebrow')}</p>
          <h3>{t('threat_cmd_title')}</h3>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>{t('threat_cmd_col')}</th>
                  <th>{t('threat_cmd_status')}</th>
                </tr>
              </thead>
              <tbody>
                {commands.length === 0 && (
                  <tr><td colSpan={2} className="empty">{t('threat_cmd_empty')}</td></tr>
                )}
                {commands.slice(0, 12).map((row, idx) => {
                  const r = asRecord(row)
                  return (
                    <tr key={`${pick(r, 'id', 'command', 'cmd')}-${idx}`}>
                      <td className="mono">{pick(r, 'command', 'cmd', 'type', 'name')}</td>
                      <td className="muted">{pick(r, 'status', 'state', 'result')}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </article>
      </div>

      <div className={`accordion ${accountsOpen ? 'open' : ''}`}>
        <button
          type="button"
          className="accordion-trigger"
          aria-expanded={accountsOpen}
          onClick={() => setAccountsOpen((v) => !v)}
        >
          <div>
            <p className="eyebrow">{t('threat_ir_eyebrow')}</p>
            <h3>{t('threat_users_title')}</h3>
            <p className="muted">
              {t('threat_card_accounts_meta', {
                active: userCounts.active,
                disabled: userCounts.disabled,
              })}
              {currentUser ? ` · ${t('threat_you_are', { user: currentUser })}` : ''}
            </p>
          </div>
          <span className="accordion-chevron" aria-hidden>▾</span>
        </button>
        <div className="accordion-body">
          <p className="muted" style={{ marginBottom: 12 }}>{t('threat_users_blurb')}</p>
          <div className="table-wrap">
            <table className="accounts-table">
              <thead>
                <tr>
                  <th>{t('threat_col_user')}</th>
                  <th>{t('threat_col_status')}</th>
                  <th>{t('threat_col_groups')}</th>
                  <th>{t('threat_col_session')}</th>
                  <th>{t('threat_col_last_logon')}</th>
                  <th className="actions-head">{t('threat_col_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty">{t('threat_users_empty')}</td>
                  </tr>
                )}
                {users.map((u) => {
                  const groups = (u.groups || []).join(', ') || '—'
                  return (
                    <tr key={u.username} className={u.is_self ? 'row-self' : undefined}>
                      <td>
                        <div className="account-name">
                          <strong className="mono">{u.username}</strong>
                          {u.is_self && <span className="pill self">{t('threat_badge_you')}</span>}
                          {u.is_admin && <span className="pill admin">{t('threat_badge_admin')}</span>}
                          {u.protected && <span className="pill muted">{t('threat_badge_protected')}</span>}
                        </div>
                        {u.full_name ? <small className="muted">{u.full_name}</small> : null}
                      </td>
                      <td>
                        <span className={`pill ${u.enabled ? 'ok' : 'off'}`}>
                          {u.enabled ? t('threat_status_active') : t('threat_status_disabled')}
                        </span>
                      </td>
                      <td className="muted">{groups}</td>
                      <td className="muted">
                        {u.has_session
                          ? (u.session_status || t('threat_session_yes'))
                          : t('threat_session_no')}
                      </td>
                      <td className="muted mono">{formatLogon(u.last_logon)}</td>
                      <td className="actions-cell">
                        <div className="ip-row-actions">
                          {u.can_logoff && (
                            <IconBtn
                              icon={icons.logoff}
                              title={t('threat_logoff')}
                              disabled={busy}
                              onClick={() => void runIr('logoff', u.username)}
                            />
                          )}
                          {u.can_disable && (
                            <IconBtn
                              icon={icons.disable}
                              title={t('threat_disable')}
                              danger
                              disabled={busy}
                              onClick={() => void runIr('disable', u.username)}
                            />
                          )}
                          {u.can_enable && (
                            <IconBtn
                              icon={icons.ok}
                              title={t('threat_enable')}
                              disabled={busy}
                              onClick={() => void runIr('enable', u.username)}
                            />
                          )}
                          {u.can_reset_password && (
                            <IconBtn
                              icon={icons.password}
                              title={t('threat_password')}
                              disabled={busy}
                              onClick={() => {
                                setPwdUser(u.username)
                                setPwdValue('')
                              }}
                            />
                          )}
                          {u.is_self && !u.can_disable && !u.can_logoff && (
                            <span
                              className="icon-btn tip tip-info"
                              tabIndex={0}
                              data-tooltip={t('threat_self_hint')}
                              aria-label={t('threat_self_hint')}
                            >
                              <FontAwesomeIcon icon={icons.info} fixedWidth />
                            </span>
                          )}
                        </div>
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
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {detail === 'threat' && (
        <DetailModal
          title={t('threat_attackers_title')}
          eyebrow={t('threat_attackers_eyebrow')}
          blurb={t('threat_attackers_blurb')}
          rows={[
            { label: t('threat_card_listed'), value: String(attackers.length) },
            { label: t('threat_card_context'), value: String(total) },
            {
              label: t('threat_detail_top_score'),
              value: attackers.length
                ? pick(asRecord(attackers[0]), 'score', 'threat_score')
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
