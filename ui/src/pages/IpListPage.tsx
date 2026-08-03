import { type FormEvent, useEffect, useMemo, useState } from 'react'
import { motorBridge } from '../bridge'
import { DataTable, type DataColumn } from '../components/DataTable'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { IconBtn, icons } from '../components/IconBtn'
import { RowActionMenu } from '../components/RowActionMenu'
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

type IpTab = 'watching' | 'blocked' | 'whitelist'

export function IpListPage({ onToast }: Props) {
  const [ip, setIp] = useState('')
  const [watching, setWatching] = useState<IpRow[]>([])
  const [blocked, setBlocked] = useState<IpRow[]>([])
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [pageHelp, setPageHelp] = useState(false)
  const [tab, setTab] = useState<IpTab>('blocked')

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

  const watchColumns = useMemo<DataColumn<IpRow>[]>(() => [
    {
      id: 'ip',
      header: t('status_ip_watching'),
      searchText: (row) => `${row.ip} ${row.reason || ''}`,
      cell: (row) => (
        <>
          <div className="mono">{row.ip}</div>
          <small className="muted">{row.reason || pick(asRecord(row), 'reason')}</small>
        </>
      ),
    },
    {
      id: 'actions',
      header: '',
      headerClassName: 'actions-head',
      className: 'actions-cell',
      cell: (row) => (
        <RowActionMenu
          primary={[{ id: 'block', label: t('btn_block'), danger: true, disabled: busy, onClick: () => void mutate('BLOCK_IP', row.ip) }]}
          more={[
            {
              id: 'wl',
              label: t('btn_whitelist_add'),
              disabled: busy,
              onClick: () => void setWhitelistIps(Array.from(new Set([...whitelist, row.ip]))),
            },
          ]}
        />
      ),
    },
  ], [busy, whitelist])

  const blockedColumns = useMemo<DataColumn<IpRow>[]>(() => [
    {
      id: 'ip',
      header: t('iplist_blocked'),
      searchText: (row) => `${row.ip} ${row.reason || ''}`,
      cell: (row) => (
        <>
          <div className="mono">{row.ip}</div>
          <small className="muted">{row.reason || '—'}</small>
        </>
      ),
    },
    {
      id: 'actions',
      header: '',
      headerClassName: 'actions-head',
      className: 'actions-cell',
      cell: (row) => (
        <RowActionMenu
          primary={[{ id: 'unblock', label: t('btn_unblock'), disabled: busy, onClick: () => void mutate('UNBLOCK_IP', row.ip) }]}
          more={[
            {
              id: 'wl',
              label: t('btn_whitelist_add'),
              disabled: busy,
              onClick: () => void setWhitelistIps(Array.from(new Set([...whitelist, row.ip]))),
            },
          ]}
        />
      ),
    },
  ], [busy, whitelist])

  const wlColumns = useMemo<DataColumn<string>[]>(() => [
    {
      id: 'ip',
      header: t('iplist_whitelist'),
      className: 'mono',
      searchText: (entry) => entry,
      cell: (entry) => entry,
    },
    {
      id: 'actions',
      header: '',
      headerClassName: 'actions-head',
      className: 'actions-cell',
      cell: (entry) => (
        <IconBtn
          icon={icons.removeWhitelist}
          title={t('iplist_exclude')}
          disabled={busy}
          onClick={() => void setWhitelistIps(whitelist.filter((x) => x !== entry))}
        />
      ),
    },
  ], [busy, whitelist])

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('iplist_eyebrow')}</p>
          <h2>{t('iplist_title')}</h2>
          <p className="muted">{t('iplist_blurb')}</p>
        </div>
        <div className="btn-row">
          <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
            {t('help_more')}
          </button>
          <button type="button" className="btn danger" disabled={busy} onClick={() => void clearAll()}>
            {t('btn_clear_blocks')}
          </button>
        </div>
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

      <nav className="page-tabs" aria-label={t('iplist_title')}>
        {(
          [
            ['watching', t('iplist_tab_watching'), watching.length],
            ['blocked', t('iplist_tab_blocked'), blocked.length],
            ['whitelist', t('iplist_tab_whitelist'), whitelist.length],
          ] as Array<[IpTab, string, number]>
        ).map(([id, label, count]) => (
          <button
            key={id}
            type="button"
            className={`page-tab${tab === id ? ' active' : ''}`}
            onClick={() => setTab(id)}
          >
            {label}
            <span className="tab-count">{count}</span>
          </button>
        ))}
      </nav>

      <article className="panel">
        {tab === 'watching' && (
          <DataTable
            rows={watching}
            rowKey={(row) => `w-${row.ip}`}
            empty={t('status_ip_empty_watch')}
            defaultPageSize={25}
            columns={watchColumns}
          />
        )}
        {tab === 'blocked' && (
          <DataTable
            rows={blocked}
            rowKey={(row) => `b-${row.ip}`}
            empty={t('iplist_empty_blocked')}
            defaultPageSize={25}
            columns={blockedColumns}
          />
        )}
        {tab === 'whitelist' && (
          <DataTable
            rows={whitelist}
            rowKey={(entry) => entry}
            empty={t('iplist_empty_wl')}
            defaultPageSize={25}
            columns={wlColumns}
          />
        )}
      </article>

      {pageHelp && (
        <DetailModal
          title={t('iplist_title')}
          eyebrow={t('iplist_eyebrow')}
          blurb={t('iplist_blurb')}
          guide={<FeatureGuide prefix="help_ip" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
