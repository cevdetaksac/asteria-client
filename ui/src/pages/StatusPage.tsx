import { useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { IconBtn, icons } from '../components/IconBtn'
import { t } from '../i18n'
import { asRecord, boolLabel, formatBps, pick } from '../lib'

type Props = {
  status: MotorStatus | null
  online: boolean
  updatedAt: string
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onNavigate: (page: 'services' | 'layers' | 'threat' | 'iplist') => void
}

type HardenCheck = {
  id?: string
  label?: string
  ok?: boolean | null
  detail?: string
  fixable?: boolean
}

type IpRow = {
  ip: string
  services?: string[]
  attempts?: number
  score?: number
  reason?: string
  last_seen?: number
  status?: string
}

const IP_PREVIEW = 8

export function StatusPage({ status, online, updatedAt, onRefresh, onToast, onNavigate }: Props) {
  const running = Array.isArray(status?.running_services) ? status.running_services : []
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const rs = asRecord(status?.rs_quarantine)
  const resources = asRecord(status?.resources)
  const [checks, setChecks] = useState<HardenCheck[]>([])
  const [busy, setBusy] = useState(false)
  const [watching, setWatching] = useState<IpRow[]>([])
  const [blocked, setBlocked] = useState<IpRow[]>([])
  const [whitelist, setWhitelist] = useState<IpRow[]>([])
  const [ipTotals, setIpTotals] = useState({ watching: 0, blocked: 0, whitelist: 0 })

  const loadExtras = async () => {
    const [h, table, cloud] = await Promise.all([
      motorBridge.harden('status'),
      motorBridge.ipc('IP_TABLE'),
      motorBridge.cloud('GET', 'threats/config'),
    ])
    if (h.ok && Array.isArray(h.checks)) setChecks(h.checks as HardenCheck[])

    const watchRows = Array.isArray(table.watching) ? (table.watching as IpRow[]) : []
    const blockRows = Array.isArray(table.blocked) ? (table.blocked as IpRow[]) : []
    let wlRows = Array.isArray(table.whitelist) ? (table.whitelist as IpRow[]) : []
    const totals = asRecord(table.totals)

    // Cloud whitelist is SoT when motor local set is thin (frontend-only edge).
    if (cloud.ok && cloud.data && typeof cloud.data === 'object') {
      const wl = (cloud.data as Record<string, unknown>).whitelist_ips
      if (Array.isArray(wl)) {
        const fromCloud = wl.map(String).filter(Boolean)
        const seen = new Set(wlRows.map((r) => r.ip))
        for (const ip of fromCloud) {
          if (!seen.has(ip)) {
            wlRows.push({ ip, reason: 'whitelist', status: 'whitelisted' })
            seen.add(ip)
          }
        }
        setIpTotals({
          watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
          blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
          whitelist: Math.max(Number(totals.whitelist ?? 0) || 0, fromCloud.length),
        })
      } else {
        setIpTotals({
          watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
          blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
          whitelist: Number(totals.whitelist ?? wlRows.length) || wlRows.length,
        })
      }
    } else {
      setIpTotals({
        watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
        blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
        whitelist: Number(totals.whitelist ?? wlRows.length) || wlRows.length,
      })
    }

    setWatching(watchRows)
    setBlocked(blockRows)
    setWhitelist(wlRows)
  }

  useEffect(() => {
    void loadExtras()
  }, [status])

  const unlockRs = async () => {
    const result = await motorBridge.ipc('RS_UNLOCK')
    onToast(result.ok ? t('toast_rs_cleared') : String(result.error || 'RS unlock'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngAccept = async () => {
    const result = await motorBridge.ipc('NG_ACCEPT_SURFACE')
    onToast(result.ok ? t('toast_ng_accept') : String(result.error || 'NG accept'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngMaint = async (start: boolean) => {
    const result = await motorBridge.ipc(start ? 'NG_MAINT_START' : 'NG_MAINT_END_SNAPSHOT')
    onToast(
      result.ok ? (start ? t('toast_ng_maint_on') : t('toast_ng_maint_off')) : String(result.error || 'NG'),
      result.ok ? 'ok' : 'err',
    )
    onRefresh()
  }

  const fixHarden = async (target: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.harden('fix', target)
      onToast(
        result.ok ? t('toast_fix_ok', { target }) : String(result.error || t('toast_fix_fail')),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const mutateIp = async (cmd: 'BLOCK_IP' | 'UNBLOCK_IP', ip: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.ipc(cmd, { ip, reason: 'status' })
      onToast(
        result.ok
          ? cmd === 'BLOCK_IP'
            ? t('toast_blocked', { ip })
            : t('toast_unblocked', { ip })
          : String(result.error || 'IPC'),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  const addWhitelist = async (ip: string) => {
    setBusy(true)
    try {
      const cloud = await motorBridge.cloud('GET', 'threats/config')
      const data = cloud.ok && cloud.data && typeof cloud.data === 'object'
        ? (cloud.data as Record<string, unknown>)
        : {}
      const current = Array.isArray(data.whitelist_ips) ? data.whitelist_ips.map(String) : []
      const next = Array.from(new Set([...current, ip]))
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const removeWhitelist = async (ip: string) => {
    setBusy(true)
    try {
      const cloud = await motorBridge.cloud('GET', 'threats/config')
      const data = cloud.ok && cloud.data && typeof cloud.data === 'object'
        ? (cloud.data as Record<string, unknown>)
        : {}
      const current = Array.isArray(data.whitelist_ips) ? data.whitelist_ips.map(String) : []
      const next = current.filter((x) => x !== ip)
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const hostCpu = pick(resources, 'host_cpu_percent', 'cpu_percent', 'cpu')
  const hostRam = pick(resources, 'host_memory_percent', 'ram_percent', 'memory_percent')
  const procCpu = pick(resources, 'process_cpu_percent')
  const procRam = pick(resources, 'process_rss_mb')
  const netDown = formatBps(resources.net_recv_bps)
  const netUp = formatBps(resources.net_sent_bps)

  const renderIpCol = (
    title: string,
    rows: IpRow[],
    total: number,
    emptyKey: string,
    kind: 'watching' | 'blocked' | 'whitelist',
  ) => (
    <article className="panel ip-col">
      <div className="ip-col-head">
        <div>
          <p className="eyebrow">{title}</p>
          <h3>{total}</h3>
        </div>
        <button
          type="button"
          className="btn ghost sm tip"
          data-tooltip={t('status_ip_all')}
          aria-label={t('status_ip_all')}
          onClick={() => onNavigate('iplist')}
        >
          {t('status_ip_all')}
        </button>
      </div>
      <div className="ip-col-list">
        {rows.length === 0 && <p className="muted empty-ip">{t(emptyKey)}</p>}
        {rows.slice(0, IP_PREVIEW).map((row) => (
          <div key={`${kind}-${row.ip}`} className="ip-row">
            <div className="ip-row-main">
              <strong className="mono">{row.ip}</strong>
              {kind === 'watching' && (
                <span className="ip-meta">
                  {t('status_ip_watch_meta', {
                    attempts: row.attempts ?? 0,
                    score: row.score ?? 0,
                  })}
                </span>
              )}
              <p className="ip-reason">{row.reason || '—'}</p>
            </div>
            <div className="ip-row-actions">
              {kind === 'watching' && (
                <>
                  <IconBtn
                    icon={icons.block}
                    title={t('btn_block')}
                    danger
                    disabled={busy}
                    onClick={() => void mutateIp('BLOCK_IP', row.ip)}
                  />
                  <IconBtn
                    icon={icons.whitelist}
                    title={t('btn_whitelist_add')}
                    disabled={busy}
                    onClick={() => void addWhitelist(row.ip)}
                  />
                </>
              )}
              {kind === 'blocked' && (
                <>
                  <IconBtn
                    icon={icons.unblock}
                    title={t('btn_unblock')}
                    disabled={busy}
                    onClick={() => void mutateIp('UNBLOCK_IP', row.ip)}
                  />
                  <IconBtn
                    icon={icons.whitelist}
                    title={t('btn_whitelist_add')}
                    disabled={busy}
                    onClick={() => void addWhitelist(row.ip)}
                  />
                </>
              )}
              {kind === 'whitelist' && (
                <IconBtn
                  icon={icons.removeWhitelist}
                  title={t('iplist_exclude')}
                  disabled={busy}
                  onClick={() => void removeWhitelist(row.ip)}
                />
              )}
            </div>
          </div>
        ))}
        {total > IP_PREVIEW && (
          <button type="button" className="btn ghost sm" onClick={() => onNavigate('iplist')}>
            {t('status_ip_more', { count: total - IP_PREVIEW })}
          </button>
        )}
      </div>
    </article>
  )

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('status_eyebrow')}</p>
          <h2>{online ? t('status_title_online') : t('status_title_offline')}</h2>
          <p className="muted">{t('status_blurb')}</p>
        </div>
        <button type="button" className="btn" onClick={onRefresh}>{t('btn_refresh')}</button>
      </div>

      <div className="chip-row">
        <button type="button" className={`chip ${online ? 'on' : ''}`}>
          {t('status_card_motor')} {online ? t('label_ok') : t('status_motor_down')}
        </button>
        <button type="button" className={`chip ${status?.ransomware_running ? 'on' : ''}`} onClick={() => onNavigate('layers')}>
          {t('layers_rs')} {boolLabel(status?.ransomware_running, t('label_on'), t('label_off'))}
        </button>
        <button type="button" className={`chip ${ng.running ? 'on' : ''}`} onClick={() => onNavigate('layers')}>
          NetGuard {boolLabel(ng.running, t('label_on'), t('label_off'))}
        </button>
        <button type="button" className={`chip ${running.length ? 'on' : ''}`} onClick={() => onNavigate('services')}>
          {t('status_chip_honeypot', { count: running.length })}
        </button>
        <button type="button" className={`chip ${rs.active ? 'warn' : ''}`} onClick={() => void unlockRs()}>
          {t('status_quarantine', { count: pick(rs, 'entries') })}
        </button>
      </div>

      <div className="cards">
        <article>
          <p>{t('status_card_motor')}</p>
          <strong>{online ? t('label_active') : t('status_motor_down')}</strong>
          <small>IPC 127.0.0.1:58632 · {pick(status, 'version')}</small>
        </article>
        <article>
          <p>{t('status_card_mode')}</p>
          <strong>{pick(status, 'protection_mode')}</strong>
          <small>{t('status_policy', { policy: pick(defense, 'defense_policy') })}</small>
        </article>
        <article className="clickable" onClick={() => onNavigate('services')}>
          <p>{t('status_card_honeypot')}</p>
          <strong>{running.length}</strong>
          <small>{running.length ? running.join(', ') : t('status_no_services')}</small>
        </article>
        <article className="clickable" onClick={() => onNavigate('threat')}>
          <p>{t('status_card_resources')}</p>
          <strong>{hostCpu}%</strong>
          <small>
            {t('status_ram', { ram: hostRam, updated: updatedAt || '—' })}
            {' · '}
            {t('status_proc_res', { cpu: procCpu, ram: procRam })}
            {' · '}
            ↓{netDown} ↑{netUp}
          </small>
        </article>
      </div>

      <div className="ip-cols" style={{ marginTop: 18 }}>
        {renderIpCol(t('status_ip_watching'), watching, ipTotals.watching, 'status_ip_empty_watch', 'watching')}
        {renderIpCol(t('status_ip_blocked'), blocked, ipTotals.blocked, 'status_ip_empty_blocked', 'blocked')}
        {renderIpCol(t('status_ip_whitelist'), whitelist, ipTotals.whitelist, 'status_ip_empty_wl', 'whitelist')}
      </div>

      <div className="split" style={{ marginTop: 18 }}>
        <article className="panel">
          <p className="eyebrow">{t('status_ng_eyebrow')}</p>
          <h3>{ng.maintenance ? t('status_ng_maint') : ng.drift ? t('status_ng_drift') : t('status_ng_stable')}</h3>
          <p className="muted">
            {t('status_ng_baseline', {
              version: pick(ng, 'baseline_version'),
              inet: boolLabel(ng.internet_ok, t('label_ok'), t('layers_none')),
            })}
          </p>
          <div className="btn-row">
            <button type="button" className="btn ghost" onClick={() => void ngMaint(true)}>{t('status_ng_start')}</button>
            <button type="button" className="btn ghost" onClick={() => void ngMaint(false)}>{t('status_ng_end')}</button>
            <button type="button" className="btn" onClick={() => void ngAccept()}>{t('status_ng_accept')}</button>
          </div>
        </article>
        <article className="panel">
          <p className="eyebrow">{t('status_rs_eyebrow')}</p>
          <h3>{rs.active ? t('status_rs_active') : t('status_rs_watch')}</h3>
          <p className="muted">
            {t('status_rs_meta', { canary: pick(rs, 'canary_files'), alerts: pick(rs, 'alerts_total') })}
          </p>
          <div className="btn-row">
            <button
              type="button"
              className="btn danger"
              disabled={!rs.active && Number(rs.entries || 0) === 0}
              onClick={() => void unlockRs()}
            >
              {t('status_rs_unlock')}
            </button>
          </div>
        </article>
      </div>

      <div className="split" style={{ marginTop: 18 }}>
        <article className="panel" style={{ gridColumn: '1 / -1' }}>
          <p className="eyebrow">{t('status_harden_eyebrow')}</p>
          <h3>{t('status_harden_title')}</h3>
          <p className="muted" style={{ marginBottom: 10 }}>
            {t('status_rdp_moved_hint')}
          </p>
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
      </div>
    </section>
  )
}
