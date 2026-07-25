import { type FormEvent, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

export function IpListPage({ onToast }: Props) {
  const [ip, setIp] = useState('')
  const [blocked, setBlocked] = useState<string[]>([])
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  const refresh = async () => {
    const [threat, cloud] = await Promise.all([
      motorBridge.ipc('THREAT_TOP'),
      motorBridge.cloud('GET', 'threats/config'),
    ])
    const attackers = Array.isArray(threat.attackers) ? threat.attackers : []
    const ips = attackers
      .map((row) => pick(asRecord(row), 'ip', 'src_ip'))
      .filter((value) => value !== '—')
    setBlocked(Array.from(new Set(ips)))
    if (cloud.ok && cloud.data && typeof cloud.data === 'object') {
      const data = cloud.data as Record<string, unknown>
      const wl = data.whitelist_ips
      setWhitelist(Array.isArray(wl) ? wl.map(String) : [])
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

      <div className="split">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('iplist_threat_ip')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {blocked.length === 0 && (
                <tr><td colSpan={2} className="empty">{t('iplist_empty_threat')}</td></tr>
              )}
              {blocked.map((entry) => (
                <tr key={entry}>
                  <td className="mono">{entry}</td>
                  <td>
                    <button type="button" className="btn danger sm" disabled={busy} onClick={() => void mutate('BLOCK_IP', entry)}>{t('btn_block')}</button>
                    <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void mutate('UNBLOCK_IP', entry)}>{t('btn_remove')}</button>
                    <button type="button" className="btn ghost sm" disabled={busy} onClick={() => void setWhitelistIps(Array.from(new Set([...whitelist, entry])))}>{t('iplist_wl_short')}</button>
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
