import { type FormEvent, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type IpRow = {
  ip: string
  reason?: string
  attempts?: number
  score?: number
  status?: string
}

export function IpListPage({ onToast }: Props) {
  const [ip, setIp] = useState('')
  const [watching, setWatching] = useState<IpRow[]>([])
  const [blocked, setBlocked] = useState<IpRow[]>([])
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  const refresh = async () => {
    const [table, cloud] = await Promise.all([
      motorBridge.ipc('IP_TABLE'),
      motorBridge.cloud('GET', 'threats/config'),
    ])
    setWatching(Array.isArray(table.watching) ? (table.watching as IpRow[]) : [])
    setBlocked(Array.isArray(table.blocked) ? (table.blocked as IpRow[]) : [])
    if (cloud.ok && cloud.data && typeof cloud.data === 'object') {
      const data = cloud.data as Record<string, unknown>
      const wl = data.whitelist_ips
      setWhitelist(Array.isArray(wl) ? wl.map(String) : [])
    } else if (Array.isArray(table.whitelist)) {
      setWhitelist((table.whitelist as IpRow[]).map((r) => String(r.ip || '')).filter(Boolean))
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const mutate = async (cmd: 'BLOCK_IP' | 'UNBLOCK_IP', target: string) => {
    if (!target.trim()) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc(cmd, { ip: target.trim(), reason: 'iplist' })
      onToast(
        result.ok
          ? cmd === 'BLOCK_IP'
            ? t('toast_blocked', { ip: target })
            : t('toast_unblocked', { ip: target })
          : String(result.error || 'IPC'),
        result.ok ? 'ok' : 'err',
      )
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  const setWhitelistIps = async (next: string[]) => {
    setBusy(true)
    try {
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  const clearAll = async () => {
    if (!window.confirm(t('iplist_confirm_clear'))) return
    setBusy(true)
    try {
      const result = await motorBridge.ipc('CLEAR_FIREWALL')
      onToast(result.ok ? t('toast_fw_cleared') : String(result.error || 'CLEAR_FIREWALL'), result.ok ? 'ok' : 'err')
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    void mutate('BLOCK_IP', ip).then(() => setIp(''))
  }

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('iplist_eyebrow')}</p>
          <h2>{t('iplist_title')}</h2>
          <p className="muted">{t('iplist_blurb')}</p>
        </div>
        <button type="button" className="btn danger" disabled={busy} onClick={() => void clearAll()}>
          {t('btn_clear_blocks')}
        </button>
      </div>

      <form className="inline-form" onSubmit={onSubmit}>
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder={t('iplist_ip_ph')}
          aria-label={t('iplist_ip_ph')}
          className="mono"
        />
        <button type="submit" className="btn" disabled={busy || !ip.trim()}>{t('btn_block')}</button>
        <button type="button" className="btn ghost" disabled={busy || !ip.trim()} onClick={() => void mutate('UNBLOCK_IP', ip)}>
          {t('btn_unblock')}
        </button>
        <button
          type="button"
          className="btn ghost"
          disabled={busy || !ip.trim()}
          onClick={() => void setWhitelistIps(Array.from(new Set([...whitelist, ip.trim()])))}
        >
          {t('btn_whitelist_add')}
        </button>
      </form>

      <div className="ip-cols" style={{ marginTop: 18 }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('status_ip_watching')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {watching.length === 0 && (
                <tr><td colSpan={2} className="empty">{t('status_ip_empty_watch')}</td></tr>
              )}
              {watching.map((row) => (
                <tr key={`w-${row.ip}`}>
                  <td>
                    <div className="mono">{row.ip}</div>
                    <small className="muted">{row.reason || pick(asRecord(row), 'reason')}</small>
                  </td>
                  <td>
                    <button type="button" className="btn danger sm" disabled={busy} onClick={() => void mutate('BLOCK_IP', row.ip)}>{t('btn_block')}</button>
                    <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void setWhitelistIps(Array.from(new Set([...whitelist, row.ip])))}>{t('iplist_wl_short')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('iplist_blocked')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {blocked.length === 0 && (
                <tr><td colSpan={2} className="empty">{t('iplist_empty_blocked')}</td></tr>
              )}
              {blocked.map((row) => (
                <tr key={`b-${row.ip}`}>
                  <td>
                    <div className="mono">{row.ip}</div>
                    <small className="muted">{row.reason || '—'}</small>
                  </td>
                  <td>
                    <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void mutate('UNBLOCK_IP', row.ip)}>{t('btn_unblock')}</button>
                    <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void setWhitelistIps(Array.from(new Set([...whitelist, row.ip])))}>{t('iplist_wl_short')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('iplist_whitelist')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {whitelist.length === 0 && (
                <tr><td colSpan={2} className="empty">{t('iplist_empty_wl')}</td></tr>
              )}
              {whitelist.map((entry) => (
                <tr key={entry}>
                  <td className="mono">{entry}</td>
                  <td>
                    <button
                      type="button"
                      className="btn ghost sm"
                      disabled={busy}
                      onClick={() => void setWhitelistIps(whitelist.filter((x) => x !== entry))}
                    >
                      {t('iplist_exclude')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
