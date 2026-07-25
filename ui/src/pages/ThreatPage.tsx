import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { useCallback, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
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

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshThreats(), refreshUsers()])
  }, [refreshThreats, refreshUsers])

  useEffect(() => {
    void refreshAll()
    const timer = window.setInterval(() => void refreshAll(), 10000)
    return () => window.clearInterval(timer)
  }, [refreshAll])

  const block = async (ip: string) => {
    if (!ip) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('BLOCK_IP', { ip, reason: 'threat_center' })
      onToast(result.ok ? t('toast_blocked', { ip }) : String(result.error || 'Block'), result.ok ? 'ok' : 'err')
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
          <button type="button" className="btn ghost" disabled={busy} onClick={() => void snapshot()}>
            {t('btn_snapshot')}
          </button>
          <button type="button" className="btn" onClick={() => void refreshAll()}>{t('btn_refresh')}</button>
        </div>
      </div>

      <div className="cards three">
        <article>
          <p>{t('threat_card_accounts')}</p>
          <strong>{userCounts.total}</strong>
          <small>
            {t('threat_card_accounts_meta', {
              active: userCounts.active,
              disabled: userCounts.disabled,
            })}
          </small>
        </article>
        <article>
          <p>{t('threat_card_listed')}</p>
          <strong>{attackers.length}</strong>
          <small>{t('threat_card_listed_meta')}</small>
        </article>
        <article>
          <p>{t('threat_card_context')}</p>
          <strong>{total}</strong>
          <small>{t('threat_card_context_meta')}</small>
        </article>
      </div>

      <article className="panel" style={{ marginBottom: 18 }}>
        <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
          <div>
            <p className="eyebrow">{t('threat_ir_eyebrow')}</p>
            <h3>{t('threat_users_title')}</h3>
            <p className="muted">
              {t('threat_users_blurb')}
              {currentUser ? ` · ${t('threat_you_are', { user: currentUser })}` : ''}
            </p>
          </div>
        </div>

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
      </article>

      <div className="page-head" style={{ marginBottom: 10, paddingBottom: 0, border: 'none' }}>
        <div>
          <p className="eyebrow">{t('threat_attackers_eyebrow')}</p>
          <h3>{t('threat_attackers_title')}</h3>
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
              <th />
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
    </section>
  )
}
