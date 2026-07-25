import { useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type Attacker = Record<string, unknown>

export function ThreatPage({ onToast }: Props) {
  const [attackers, setAttackers] = useState<Attacker[]>([])
  const [total, setTotal] = useState(0)
  const [busy, setBusy] = useState(false)
  const [irUser, setIrUser] = useState('')

  const refresh = async () => {
    const result = await motorBridge.ipc('THREAT_TOP')
    const list = Array.isArray(result.attackers) ? (result.attackers as Attacker[]) : []
    setAttackers(list)
    setTotal(Number(result.total ?? list.length) || 0)
  }

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 8000)
    return () => window.clearInterval(timer)
  }, [])

  const block = async (ip: string) => {
    if (!ip) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('BLOCK_IP', { ip, reason: 'threat_center' })
      onToast(result.ok ? t('toast_blocked', { ip }) : String(result.error || 'Block'), result.ok ? 'ok' : 'err')
      await refresh()
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

  const runIr = async (action: 'logoff' | 'disable', username?: string) => {
    const user = (username || irUser || '').trim()
    if (!user) {
      onToast(t('threat_need_user'), 'err')
      return
    }
    const confirmKey = action === 'logoff' ? 'threat_confirm_logoff' : 'threat_confirm_disable'
    if (!window.confirm(t(confirmKey, { user }))) return
    setBusy(true)
    try {
      const result = await motorBridge.ir(action, user)
      onToast(
        result.ok
          ? action === 'logoff'
            ? t('toast_logoff_ok', { user })
            : t('toast_disable_ok', { user })
          : String(result.error || 'IR'),
        result.ok ? 'ok' : 'err',
      )
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
          <button type="button" className="btn" onClick={() => void refresh()}>{t('btn_refresh')}</button>
        </div>
      </div>

      <div className="cards three">
        <article>
          <p>{t('threat_card_context')}</p>
          <strong>{total}</strong>
          <small>{t('threat_card_context_meta')}</small>
        </article>
        <article>
          <p>{t('threat_card_listed')}</p>
          <strong>{attackers.length}</strong>
          <small>{t('threat_card_listed_meta')}</small>
        </article>
        <article>
          <p>{t('threat_card_ir')}</p>
          <strong>IR</strong>
          <small>{t('threat_card_ir_meta')}</small>
        </article>
      </div>

      <article className="panel" style={{ marginBottom: 18 }}>
        <p className="eyebrow">{t('threat_ir_eyebrow')}</p>
        <h3>{t('threat_ir_title')}</h3>
        <div className="inline-form">
          <input
            type="text"
            placeholder={t('threat_user_ph')}
            value={irUser}
            onChange={(e) => setIrUser(e.target.value)}
          />
          <button type="button" className="btn ghost" disabled={busy} onClick={() => void runIr('logoff')}>
            {t('threat_logoff')}
          </button>
          <button type="button" className="btn danger" disabled={busy} onClick={() => void runIr('disable')}>
            {t('threat_disable')}
          </button>
        </div>
      </article>

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
                  <td>
                    <div className="btn-row">
                      <button type="button" className="btn danger sm" disabled={busy || ip === '—'} onClick={() => void block(ip)}>
                        {t('btn_block')}
                      </button>
                      {user !== '—' && (
                        <>
                          <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void runIr('logoff', user)}>
                            {t('threat_logoff')}
                          </button>
                          <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void runIr('disable', user)}>
                            {t('threat_disable')}
                          </button>
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
